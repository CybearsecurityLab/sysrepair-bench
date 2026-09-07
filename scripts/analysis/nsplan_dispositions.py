#!/usr/bin/env python3
"""Recompute the NeuroPlan Val/Plan/Exec table and per-scenario dispositions.

This is the stage decomposition behind tab:nsplan. Every scenario ends in
exactly one disposition, and the point of the table is WHERE it ended, not just
whether it passed:

    validate-fail   the generated PDDL never validated. No plan, no execution,
                    nothing reached the host.
    plan-fail       PDDL validated, the planner returned no plan within budget.
                    Still nothing reached the host.
    execute-fail    a plan was produced and executed, and the oracle refused the
                    result. This is the ONLY bucket that mutates the target.
    success         plan executed and the dual-objective oracle passed.

The first two are refusals, and the paper's change-management argument rests on
them being refusals rather than partial edits. Emitting the disposition per
scenario is what lets a reader check that claim instead of taking it.

Execute is the oracle verdict, not the solver's self-report: a solver that says
REMEDIATION_COMPLETE while the oracle scores I is an execute-fail.

Usage:
    python nsplan_dispositions.py --logs DIR [--suite vulnhub] [--out T.tsv]
"""
from __future__ import annotations
import argparse, glob, sys
from pathlib import Path

# Stage markers the solver writes into output.completion.
VALIDATE_OK = {"PLANNER_FOUND_NO_PLAN", "PLAN_DID_NOT_REMEDIATE", "REMEDIATION_COMPLETE"}
PLAN_OK = {"PLAN_DID_NOT_REMEDIATE", "REMEDIATION_COMPLETE"}


def disposition(validated: bool, planned: bool, executed: bool) -> str:
    if not validated:
        return "validate-fail"
    if not planned:
        return "plan-fail"
    return "success" if executed else "execute-fail"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", required=True)
    ap.add_argument("--suite", default=None, help="only scenarios of this suite")
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()

    # Registers the custom sandbox provider. Without it read_eval_log raises
    # NotImplementedError on these logs and every sample is silently skipped.
    import sysrepair_bench.task  # noqa: F401
    from inspect_ai.log import read_eval_log

    files = sorted(glob.glob(f"{a.logs}/*.eval"))
    if not files:
        print(f"ERROR: no .eval logs under {a.logs}", file=sys.stderr)
        return 2

    rows: dict[str, dict] = {}
    for f in files:
        try:
            log = read_eval_log(f)
        except Exception as e:
            print(f"WARNING: unreadable, skipped: {Path(f).name}: "
                  f"{type(e).__name__}", file=sys.stderr)
            continue
        for s in (log.samples or []):
            sid = str(s.id)
            if a.suite and not sid.startswith(a.suite):
                continue
            comp = ((s.output.completion if s.output else "") or "").strip()
            # Plan length is the count of LOWERED COMMANDS that actually reached
            # the harness, recovered from the transcript markers, not a metadata
            # field: the metadata value counts operators before lowering and so
            # disagrees with the paper.
            plen = sum(
                1 for m in (s.messages or [])
                if isinstance(getattr(m, "content", "") or "", str)
                and "[neurosym:plan] $" in (m.content or ""))
            sc = (s.scores or {}).get("dispatch_scorer")
            executed = getattr(sc, "value", None) == "C" if sc else False
            try:
                toks = sum(u.total_tokens for u in (log.stats.model_usage or {}).values())
            except Exception:
                toks = 0
            rows[sid] = dict(comp=comp, val=comp in VALIDATE_OK,
                             plan=comp in PLAN_OK, exe=executed,
                             plen=plen, toks=toks)

    n = len(rows)
    if not n:
        print(f"ERROR: no samples matched under {a.logs}", file=sys.stderr)
        return 2
    V = sum(r["val"] for r in rows.values())
    P = sum(r["plan"] for r in rows.values())
    E = sum(r["exe"] for r in rows.values())
    plens = [r["plen"] for r in rows.values() if r["plan"]]
    toks = sum(r["toks"] for r in rows.values())

    lines = ["\t".join(["scenario", "disposition", "validated", "planned",
                        "executed", "plan_length"])]
    for sid in sorted(rows):
        r = rows[sid]
        lines.append("\t".join([
            sid, disposition(r["val"], r["plan"], r["exe"]),
            str(int(r["val"])), str(int(r["plan"])), str(int(r["exe"])),
            str(r["plen"])]))
    lines.append("")
    lines.append("\t".join(["SUMMARY", "n", "validate", "plan", "execute",
                            "mean_plan_len", "tokens_per_success"]))
    lines.append("\t".join([
        "", str(n), f"{V/n:.2f}", f"{P/n:.2f}", f"{E/n:.2f}",
        f"{sum(plens)/len(plens):.1f}" if plens else "n/a",
        f"{toks/E:.0f}" if E else "n/a"]))

    text = "\n".join(lines)
    if a.out:
        a.out.write_text(text + "\n")
        print(f"wrote {a.out}")
    print(text)

    # The refusal buckets must not have touched the host. A nonzero plan length
    # in validate-fail/plan-fail would mean something was lowered and possibly
    # run, which would break the paper's refusal argument.
    bad = [s for s, r in rows.items()
           if not r["plan"] and r["plen"] and r["plen"] > 0]
    if bad:
        print(f"\nWARNING: {len(bad)} refusal-bucket scenarios carry a nonzero "
              f"plan length: {', '.join(sorted(bad))}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
