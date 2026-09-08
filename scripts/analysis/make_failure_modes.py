#!/usr/bin/env python3
"""Recompute the failure-mode distribution by information condition.

Rule-based on the oracle's structured output, deliberately not an LLM judge: a
taxonomy that changes between runs cannot be an evaluated claim.

Modes, in precedence order. Precedence matters because an episode can satisfy
more than one and the first match wins:

  unmeasured-flaky   the oracle never ran and no limit was hit -- a benchmark
                     defect, reported separately and never as a model failure
  truncated          the episode hit its budget. NOT a capability signal: the
                     solver was still working when the clock stopped
  self-bricked       the model rebooted or shut down its own target
  availability-break the exploit was fixed but a declared service stopped
                     answering -- the dual-objective oracle's whole point
  no-action          the solver issued no commands at all
  security-fail      the exploit check still succeeds after the solver acted
  passed-but-unclear no security check failed yet the episode did not pass

WHAT THIS TAXONOMY DELIBERATELY DOES NOT CLAIM. An earlier version split
security failures into "localisation" (never found the vulnerable surface) and
"execution" (found it, repaired it wrong). That split is NOT recoverable from
the oracle's output: every failing check carries a detail string whether or not
the solver ever touched the relevant surface, so any rule built on the oracle
alone silently reports one category as zero. Separating perception from action
requires reading what the solver actually did, which is a transcript analysis
and not a deterministic rule. Rather than ship a rule that looks like it
measures the distinction and does not, the security failures are reported as one
bucket and the paper's perception-versus-action reading is supported by the
transcript excerpts in artifact/transcripts/ instead.
"""
from __future__ import annotations
import argparse, collections, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import load_episodes                 # noqa: E402
from passk import prefix_pass_at                  # noqa: E402
from unmeasured import _matches_unmeasured, at_cap, _self_bricked   # noqa: E402


def classify(sample, ta):
    wl, tl = ta.get("working_limit"), ta.get("time_limit")
    capped = at_cap(sample, wl, tl)
    if _matches_unmeasured(sample):
        if capped:
            return "truncated"
        if _self_bricked(sample):
            return "self-bricked"
        return "unmeasured-flaky"
    if capped:
        return "truncated"
    if _self_bricked(sample):
        return "self-bricked"
    checks = []
    for _, sc in (getattr(sample, "scores", None) or {}).items():
        checks = (getattr(sc, "metadata", None) or {}).get("checks") or checks
    if _no_commands(sample):
        return "no-action"
    if checks:
        sec = [c for c in checks if c.get("kind") == "poc"]
        reg = [c for c in checks if c.get("kind") == "regression"]
        if reg and not all(c.get("pass") for c in reg):
            return "availability-break"
        if sec and not all(c.get("pass") for c in sec):
            return "security-fail"
        return "passed-but-unclear"
    return "security-fail"


def _no_commands(sample) -> bool:
    """Did the solver take no action on the host at all?

    Counts BOTH routes to the sandbox, because solvers differ:

      messages[].tool_calls   react, basic, reflexion -- the model calls a tool
      SandboxEvent            plan_and_solve -- this drives the sandbox
                              directly and emit NO tool_calls at all

    Checking only tool_calls classified every plan_and_solve failure as
    "no action" when they had issued dozens of commands: one sampled episode
    showed 0 tool_calls against 95 SandboxEvents. That inflated the no-action
    bucket to 65% of day-1 failures.
    """
    for m in (getattr(sample, "messages", None) or []):
        if getattr(m, "tool_calls", None):
            return False
    for e in (getattr(sample, "events", None) or []):
        if type(e).__name__ == "SandboxEvent":
            return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", required=True, type=Path)
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()
    if not a.logs.exists():
        print(f"ERROR: no log directory {a.logs}", file=sys.stderr); return 2

    from sysrepair_bench.passk import _attempt_outcomes
    eps = load_episodes(a.logs)
    counts = collections.defaultdict(collections.Counter)
    for key, (s, ta) in eps.items():
        if prefix_pass_at(_attempt_outcomes(s), a.k):
            continue
        counts[key[2]][classify(s, ta)] += 1

    modes = ["security-fail", "availability-break", "no-action",
             "passed-but-unclear", "truncated", "self-bricked", "unmeasured-flaky"]
    lines = ["\t".join(["cond", "mode", "count", "pct_of_failures"])]
    for cond in sorted(counts):
        tot = sum(counts[cond].values())
        for m in modes:
            c = counts[cond][m]
            lines.append("\t".join([("D1" if cond == "day1" else "0D"), m, str(c),
                                    f"{100*c/tot:.1f}" if tot else "-"]))
    text = "\n".join(lines)
    print(text)
    if a.out:
        a.out.write_text(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
