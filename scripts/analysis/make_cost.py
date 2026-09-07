#!/usr/bin/env python3
"""Recompute the cost table: tokens and dollars per success, per solver.

Denominator is SUCCESSFUL scenarios, so a solver that never succeeds has no
defined cost per success and is reported as such rather than as infinity or a
silent omission.
"""
from __future__ import annotations
import argparse, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import load_episodes, group          # noqa: E402
from passk import prefix_pass_at                  # noqa: E402
from pricing import cost_usd, SNAPSHOT_DATE       # noqa: E402


def tokens(sample):
    """(input, output, total) for one episode, tolerating absent usage."""
    mu = getattr(sample, "model_usage", None) or {}
    i = o = t = 0
    for _, u in mu.items():
        i += getattr(u, "input_tokens", 0) or 0
        o += getattr(u, "output_tokens", 0) or 0
        t += getattr(u, "total_tokens", 0) or 0
    return i, o, t


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", required=True, type=Path)
    ap.add_argument("--model", default="minimax-m2.7")
    ap.add_argument("--mode", default="day1")
    ap.add_argument("--k", type=int, default=1)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()
    if not a.logs.exists():
        print(f"ERROR: no log directory {a.logs}", file=sys.stderr); return 2

    eps = load_episodes(a.logs, mode=a.mode)
    eps = {k: v for k, v in eps.items() if k[0] == a.model.lower()}
    if not eps:
        print(f"ERROR: no {a.model} {a.mode} episodes under {a.logs}", file=sys.stderr); return 2

    from sysrepair_bench.passk import _attempt_outcomes
    lines = ["\t".join(["solver", "successes", "n", "tok_per_success", "usd_per_success",
                        "total_tokens"])]
    for (solver,), items in sorted(group(eps, "solver").items()):
        succ = ti = to = tt = 0
        for _, (s, _ta) in items:
            i, o, t = tokens(s); ti += i; to += o; tt += t
            if prefix_pass_at(_attempt_outcomes(s), a.k):
                succ += 1
        if succ:
            tps = f"{tt/succ:.0f}"
            ups = f"{cost_usd(a.model, ti, to, tt)/succ:.3f}"
        else:
            tps = ups = "undefined"     # no successes: cost per success has no value
        lines.append("\t".join([str(solver), str(succ), str(len(items)), tps, ups, str(tt)]))

    text = "\n".join(lines)
    print(f"# pricing snapshot {SNAPSHOT_DATE}; cached tokens estimated as total-in-out")
    print(text)
    if a.out:
        a.out.write_text(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
