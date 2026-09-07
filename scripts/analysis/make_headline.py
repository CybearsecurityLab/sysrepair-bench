#!/usr/bin/env python3
"""Recompute the paper's headline accuracy table from evaluation logs.

Emits one row per (model, solver, condition, K) with the per-suite pass@K and
the overall, plus the DENOMINATOR for every cell. The denominator is printed
because a percentage on its own cannot be checked: most disagreements between a
published cell and a recomputation are population differences, not arithmetic.

Usage:
    python make_headline.py --logs DIR [--k 1,5] [--out table.tsv]
"""
from __future__ import annotations
import argparse, collections, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from passk import cell_pass_at  # noqa: E402

SUITES = ["ccdc", "meta2", "meta3", "vulnhub", "meta4"]
# meta3 is reported as one column in the paper but stored as two benchmarks.
SUITE_ALIASES = {"ubuntu": "meta3", "windows": "meta3"}
MODEL_LABEL = {
    "minimax-m2.7": "MiniMax-M2.7",
    "qwen3.5-9b": "Qwen3.5-9B",
    "qwen3.5-35b-a3b": "Qwen3.5-35B-A3B",
}


def load(logdir: Path):
    """Return {(model, solver, mode, suite): [episode outcomes]} from a log tree."""
    import sysrepair_bench  # noqa: F401  registers the sandbox provider
    from inspect_ai.log import list_eval_logs, read_eval_log
    from sysrepair_bench.passk import _attempt_outcomes, _is_not_applicable_sample

    cells = collections.defaultdict(dict)
    seen = set()
    # Quarantined trees hold runs that are invalid rather than incomplete, and
    # this walk recurses from a caller-supplied root, so exclude them here too.
    def _quarantined(path):
        return any("quarantine" in part.lower() for part in path.parts)

    for d in [logdir] + [x for x in logdir.rglob("*") if x.is_dir()]:
        if _quarantined(d):
            continue
        try:
            logs = list_eval_logs(str(d))
        except Exception:
            continue
        for i in logs:
            base = Path(str(i.name)).name
            if base in seen:
                continue
            seen.add(base)
            try:
                h = read_eval_log(i.name, header_only=True)
                log = read_eval_log(i.name, header_only=False)
            except Exception:
                continue
            # Only sysrepair episodes. The bundle also carries NeuroPlan runs
            # (task neurosymbolic_bench), which have no solver task-arg. Without
            # this they were folded into the headline table as a solver named
            # "?" sitting alongside react and basic, which is a different system
            # being reported as an LLM solver row.
            if "sysrepair" not in (h.eval.task or ""):
                continue
            ta = h.eval.task_args or {}
            model = str(h.eval.model).split("/")[-1].lower()
            solver, mode = ta.get("solver", "?"), ta.get("mode", "?")
            for s in log.samples or []:
                if _is_not_applicable_sample(s):
                    continue
                o = _attempt_outcomes(s)
                if not o:
                    continue
                meta = s.metadata or {}
                b = meta.get("benchmark")
                b = SUITE_ALIASES.get(b, b)
                sid = meta.get("scenario_id") or str(s.id)
                # dedupe on (scenario, epoch): one episode contributes once
                cells[(model, solver, mode, b)][(sid, getattr(s, "epoch", None))] = o
    return cells


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", required=True, type=Path)
    ap.add_argument("--k", default="1,5")
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()
    if not a.logs.exists():
        print(f"ERROR: log directory not found: {a.logs}", file=sys.stderr)
        return 2
    ks = [int(x) for x in a.k.split(",")]
    cells = load(a.logs)
    if not cells:
        print(f"ERROR: no readable eval logs under {a.logs}", file=sys.stderr)
        return 2

    lines = ["\t".join(["model", "solver", "cond", "K"] +
                       [f"{s}\t{s}_n" for s in SUITES] + ["overall", "overall_n"])]
    keys = sorted({(m, sv, md) for (m, sv, md, _) in cells})
    for model, solver, mode in keys:
        for k in ks:
            row, tot_p, tot_n = [], 0, 0
            for suite in SUITES:
                eps = list(cells.get((model, solver, mode, suite), {}).values())
                p, n = cell_pass_at(eps, k)
                tot_p += p; tot_n += n
                row += [f"{100*p/n:.1f}" if n else "-", str(n)]
            ov = f"{100*tot_p/tot_n:.1f}" if tot_n else "-"
            cond = "D1" if mode == "day1" else "0D"
            lines.append("\t".join([MODEL_LABEL.get(model, model), solver, cond, str(k)]
                                   + row + [ov, str(tot_n)]))
    text = "\n".join(lines)
    print(text)
    if a.out:
        a.out.write_text(text + "\n")
        print(f"\nwrote {a.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
