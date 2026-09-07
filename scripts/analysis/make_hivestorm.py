#!/usr/bin/env python3
"""Recompute the Hivestorm table: per-scenario normalised score and the mean.

Hivestorm is scored differently from every other suite and this script exists to
make that visible rather than to hide it. Elsewhere the oracle is a binary
dual-objective verdict; here the scorer awards points incrementally and may be
invoked several times during a run. The paper reports ONE run per scenario, so
these numbers carry no interval and are not comparable to the pass@K cells.

Both the raw points and the per-scenario maximum are printed, so a reader can
see the normalisation rather than take the ratio on trust.
"""
from __future__ import annotations
import argparse, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import load_episodes    # noqa: E402


def score_of(sample):
    """(points, max_points) for one Hivestorm episode."""
    for _, sc in (getattr(sample, "scores", None) or {}).items():
        md = getattr(sc, "metadata", None) or {}
        pts, mx = md.get("points"), md.get("points_max")
        if pts is not None and mx:
            return float(pts), float(mx)
        checks = md.get("checks") or []
        if checks:                      # fall back to the check list
            got = sum(1 for c in checks if c.get("pass"))
            return float(got), float(len(checks))
    return None, None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", required=True, type=Path)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()
    if not a.logs.exists():
        print(f"ERROR: no log directory {a.logs}", file=sys.stderr); return 2

    eps = {k: v for k, v in load_episodes(a.logs, mode="zero_day").items()
           if k[3] == "hivestorm"}
    if not eps:
        print(f"ERROR: no hivestorm zero_day episodes under {a.logs}", file=sys.stderr); return 2

    rows, norms = [], []
    for key in sorted(eps, key=lambda k: str(k[4])):
        s, _ta = eps[key]
        pts, mx = score_of(s)
        if pts is None:
            rows.append((str(key[4]), "-", "-", "-")); continue
        n = pts / mx if mx else 0.0
        norms.append(n)
        rows.append((str(key[4]), f"{pts:.1f}", f"{mx:.1f}", f"{100*n:.1f}"))

    lines = ["\t".join(["scenario", "points", "points_max", "normalised_pct"])]
    lines += ["\t".join(r) for r in rows]
    if norms:
        lines.append("\t".join(["MEAN", "-", "-", f"{100*sum(norms)/len(norms):.1f}"]))
    text = "\n".join(lines)
    print(text)
    print(f"\n# {len(norms)} scenarios scored, single run each, no interval", file=sys.stderr)
    if a.out:
        a.out.write_text(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
