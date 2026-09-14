"""Emit the CODASPY headline table from the refolded cells.

Reads the CSV that `codaspy_refold.py` writes and prints a LaTeX table body.
Nothing is typed by hand, so the table cannot drift from the logs.

Two rules it enforces that the previous table did not:

1. **The full design matrix is shown.** Every (model, solver, condition, suite)
   appears. A cell with no data prints an en dash and carries no annotation,
   because a results table is not a progress tracker.
2. **`Ovr.` is the episode-weighted mean of the row's own cells, and nothing
   else.** The old Ovr column was not derivable from its row, which is why
   reviewers could not reproduce it. It is now reported with the Wilson
   interval and the number of scenarios behind it, so a reader can see that a
   3-suite single-epoch row is not the same evidence as a 5-suite
   five-epoch one.

Usage:
    python make_headline_table.py cells.csv > table.tex
"""
from __future__ import annotations

import csv
import math
import sys
from collections import defaultdict

# Column order and the header label for each suite.
SUITES = [("ccdc", "CC"), ("meta2", "M2"), ("ubuntu", "M3"),
          ("vulnhub", "VH"), ("meta4", "M4"), ("hivestorm", "HS")]

SOLVER_LABEL = {"react": "ReAct", "reflexion": "Reflexion", "basic": "Basic",
                "plan_and_solve": "Plan-Solve"}
SOLVER_ORDER = ["react", "reflexion", "basic", "plan_and_solve"]
MODEL_ORDER = ["MiniMax-M2.7", "Qwen3.5-9B"]
DASH = "--"


def wilson(p: float, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (100 * max(0.0, c - h), 100 * min(1.0, c + h))


# A cell must cover this fraction of its suite to be reported at all.
# Below it, the cell is a biased subset rather than a measurement of the suite:
# Qwen reflexion zero-day on ubuntu covered 1 scenario of 19 and read as 100%,
# and Qwen basic on meta4 covered 33 of 113 and read as 97%. Printing those
# next to a five-epoch full-suite cell invites a comparison the data cannot
# support, so they are dashed like any other absent cell.
MIN_COVERAGE = 0.9


def main() -> int:
    path = sys.argv[1]
    rows = list(csv.DictReader(open(path)))
    by = {}
    for r in rows:
        by[(r["model"], r["solver"], r["condition"], r["suite"])] = r

    # Per-suite scenario count, taken from the widest cell that ran it.
    suite_n: dict[str, int] = defaultdict(int)
    for r in rows:
        key = r["suite"]
        suite_n[key] = max(suite_n[key], int(r.get("n_scenarios") or 0))

    dropped = 0
    for key, r in list(by.items()):
        cov = int(r.get("n_scenarios") or 0) / max(1, suite_n[r["suite"]])
        if cov < MIN_COVERAGE:
            del by[key]
            dropped += 1
    print(f"% {dropped} cells below {MIN_COVERAGE:.0%} suite coverage, dashed",
          file=sys.stderr)

    out: list[str] = []
    head = " & ".join(lbl for _, lbl in SUITES)
    out.append(r"    Model & Solver & C.@$K$ & " + head + r" & Ovr.\,[95\% CI] & Sc. \\")
    sizes = " & ".join(rf"\tiny{{({suite_n[s]})}}" for s, _ in SUITES)
    out.append(r"     &  &  & " + sizes + r" &  &  \\")
    out.append(r"    \midrule")

    for mi, model in enumerate(MODEL_ORDER):
        if mi:
            out.append(r"    \midrule")
        out.append(rf"    \multirow{{16}}{{*}}{{\rotatebox{{90}}{{{model}}}}}")
        for si, solver in enumerate(SOLVER_ORDER):
            if si:
                out.append(r"      \cmidrule(l){2-11}")
            for cond, ctag in (("day1", "D1"), ("zero_day", "0D")):
                for k in ("1", "5"):
                    cells, num, den, scen = [], 0.0, 0, 0
                    for suite, _ in SUITES:
                        r = by.get((model, solver, cond, suite))
                        if r is None:
                            cells.append(DASH)
                            continue
                        v = float(r[f"pass{k}"])
                        n = int(r["n"])
                        cells.append(f"{v:.0f}")
                        num += v * n
                        den += n
                        scen += int(r.get("n_scenarios") or 0)
                    if den == 0:
                        out.append(f"      & {SOLVER_LABEL[solver]:<10} & {ctag}@{k} & "
                                   + " & ".join(cells)
                                   + rf" & {DASH} & {DASH} \\")
                        continue
                    ovr = num / den
                    lo, hi = wilson(ovr / 100, den)
                    out.append(f"      & {SOLVER_LABEL[solver]:<10} & {ctag}@{k} & "
                               + " & ".join(cells)
                               + rf" & {ovr:.1f}\,\tiny{{[{lo:.0f},{hi:.0f}]}} & {scen} \\")
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
