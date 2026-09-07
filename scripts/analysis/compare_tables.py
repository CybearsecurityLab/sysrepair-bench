#!/usr/bin/env python3
"""Compare a recomputed table against the expected one, cell by cell.

Reports three outcomes per row, and they are deliberately distinct:

  MATCH             recomputed value equals expected within tolerance
  DIFFERS           both sides have data and they disagree
  NOT REPRODUCIBLE  expected has a value, recomputed has no episodes for it

The third case exists because a published cell whose logs did not survive must
not be reported as a failure to reproduce arithmetic. It is a gap in the shipped
data, and conflating the two would mislead an evaluator in both directions.

Denominators are compared too. A value that matches on a different denominator
is flagged, because it is a different population producing a coincidentally
similar percentage.
"""
from __future__ import annotations
import argparse, sys
from pathlib import Path


def read(p: Path):
    rows = [ln.split("\t") for ln in p.read_text().strip().splitlines()]
    head, body = rows[0], rows[1:]
    key_n = 4  # model, solver, cond, K
    return head, {tuple(r[:key_n]): r[key_n:] for r in body}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--expected", required=True, type=Path)
    ap.add_argument("--observed", required=True, type=Path)
    ap.add_argument("--tolerance", type=float, default=0.05)
    a = ap.parse_args()
    for f in (a.expected, a.observed):
        if not f.exists():
            print(f"ERROR: missing {f}", file=sys.stderr)
            return 2

    ehead, exp = read(a.expected)
    _, obs = read(a.observed)
    cols = ehead[4:]

    match = differ = missing = 0
    for key, evals in sorted(exp.items()):
        ovals = obs.get(key)
        label = " ".join(key)
        if ovals is None:
            print(f"NOT REPRODUCIBLE  {label}: no episodes in the shipped logs")
            missing += 1
            continue
        for i in range(0, len(evals), 2):
            col = cols[i]
            ev, en = evals[i], evals[i + 1]
            ov, on = ovals[i], ovals[i + 1]
            if ev == "-" and ov == "-":
                continue
            if ov == "-":
                print(f"NOT REPRODUCIBLE  {label} {col}: expected {ev} (n={en}), no data")
                missing += 1
                continue
            if ev == "-":
                # The expected table has no value here but the logs now do.
                # That is new coverage, not a mismatch, so report it and move
                # on rather than trying to float("-").
                print(f"NEW DATA          {label} {col}: no expected value, got {ov} (n={on})")
                continue
            if abs(float(ev) - float(ov)) > a.tolerance:
                print(f"DIFFERS           {label} {col}: expected {ev} (n={en}), got {ov} (n={on})")
                differ += 1
            elif en != on:
                print(f"DIFFERS           {label} {col}: value {ov} matches but n differs "
                      f"(expected {en}, got {on}) -- different population")
                differ += 1
            else:
                match += 1

    print(f"\n{match} cells match, {differ} differ, {missing} not reproducible")
    if differ:
        print("FAIL: recomputed values disagree with the paper")
        return 1
    if missing and not match:
        # Reproducing nothing is not a partial success. Exiting 0 here would
        # show an evaluator a green run for a claim that verified no cell.
        print("FAIL: no published cell could be recomputed from the shipped "
              "logs; the expected table describes a population the logs do "
              "not contain")
        return 1
    if missing:
        print(f"PARTIAL: {match} recomputable cells all match; {missing} cells "
              f"have no shipped logs")
        return 0
    print("PASS: every published cell recomputes from the shipped logs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
