"""Refold the CODASPY headline table from the logs, under ONE stated rule.

WHY. The published headline table reports pass@5 BELOW pass@1 in 22 of its 90
comparable cells. Under the paper's own protocol that is impossible: pass@5 is
a superset event of pass@1 on the same samples, so it cannot be lower. The only
way to get there is for the @1 and @5 columns to come from different run sets.
A reviewer sees this without opening a file, so every number downstream of the
table (rankings, cost per success, the Pareto frontier, the three-axis
argument) is unusable until it is refolded.

THE RULE, stated once and applied to every cell:

  1. Pool every log root.
  2. Deduplicate by log BASENAME, keeping the last. Never by full path: the
     root prefix dominates a path sort, so `logs/` beats `logs_es/` regardless
     of the ISO timestamp in the name and a stale run silently wins.
  3. An episode is keyed (model, solver, condition, suite, scenario, epoch).
  4. pass@k via the harness's own `_prefix_pass_at` with unresolved="fail",
     so an episode that never resolved counts against us.
  5. N/A samples are dropped by the harness's own predicate, not by hand.

This is the same convention `canonical_cells.py` uses for the ICLR panel, which
reproduces its 9B row exactly. It is reused rather than reinvented so the two
papers cannot drift apart.

OUTPUT. Per cell: pass@1, pass@5, the scenario count actually behind it, and a
Wilson interval. Plus a monotonicity check, which must come out at zero.

Usage:
    python codaspy_refold.py                 # every cell
    python codaspy_refold.py --csv out.csv
"""
from __future__ import annotations

import argparse
import csv
import math
from collections import defaultdict
from pathlib import Path

import sysrepair_bench  # noqa: F401  (registers the sandbox provider)
from inspect_ai.log import list_eval_logs, read_eval_log
from sysrepair_bench.passk import (  # noqa: E402
    _attempt_outcomes, _prefix_pass_at, _mean, _is_not_applicable_sample,
)

ROOTS = ["logs", "logs_es", "logs_backup", "inspect_eval/logs",
         "inspect_eval/logs_es", "inspect_eval/logs_backup"]

# The two subject models of this paper, matched loosely against the model
# string in the log header.
MODELS = {"m2.7": "MiniMax-M2.7", "minimax-m2": "MiniMax-M2.7",
          "qwen3.5-9b": "Qwen3.5-9B", "9b": "Qwen3.5-9B"}

# LATS is out of the paper; it is dropped here rather than folded and discarded
# later, so it cannot reappear in a derived number.
SOLVERS = ("basic", "react", "reflexion", "plan_and_solve")

SUITES = ("ccdc", "meta2", "meta3/ubuntu", "ubuntu", "vulnhub", "meta4")


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval. Reported instead of a bare point estimate because
    the per-suite N here runs from 19 to 137 and the interval width is not
    remotely constant across the columns of one row."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (100 * max(0.0, c - h), 100 * min(1.0, c + h))


def model_of(raw: str) -> str | None:
    low = raw.lower()
    for frag, name in MODELS.items():
        if frag in low:
            return name
    return None


def load() -> dict:
    episodes: dict[tuple, list] = {}
    source: dict[tuple, str] = {}
    source_ok: dict[tuple, bool] = {}
    source_len: dict[tuple, int] = {}
    tokens: dict[tuple, int] = {}
    seen: set[str] = set()
    files = 0
    for root in ROOTS:
        p = Path(root)
        if not p.exists():
            continue
        for d in [p] + [x for x in p.rglob("*") if x.is_dir()]:
            if d.name == "smoke":
                continue
            try:
                logs = list_eval_logs(str(d))
            except Exception:
                continue
            for item in logs:
                base = Path(str(item.name)).name
                if base in seen:
                    continue
                try:
                    head = read_eval_log(item.name, header_only=True)
                except Exception:
                    continue
                ta = head.eval.task_args or {}
                solver = ta.get("solver")
                if solver not in SOLVERS:
                    continue
                model = model_of(str(head.eval.model))
                if model is None:
                    continue
                # A partial run must not outrank a complete one. Prefer
                # status=success; the corpus is majority-incomplete and a
                # partial otherwise wins on basename order alone.
                seen.add(base)
                files += 1
                try:
                    log = read_eval_log(item.name, header_only=False)
                except Exception:
                    continue
                mode = ta.get("mode", "day1")
                ok = getattr(log, "status", None) == "success"
                for s in (log.samples or []):
                    if _is_not_applicable_sample(s):
                        continue
                    outcomes = _attempt_outcomes(s)
                    if not outcomes:
                        continue
                    meta = s.metadata or {}
                    key = (model, solver, mode, meta.get("benchmark"),
                           meta.get("scenario_id") or str(s.id),
                           getattr(s, "epoch", None))
                    # KEEP-LAST BY BASENAME, ALWAYS. The earlier form applied
                    # the ordering only when the incoming log was incomplete,
                    # so any complete log overwrote whatever was already there
                    # and DIRECTORY WALK ORDER decided the winner instead of
                    # the ISO timestamp in the name. That is the same defect
                    # this file's docstring warns about, one level in, and it
                    # silently replaced multi-attempt episodes with
                    # single-attempt ones: every ReAct day-1 cell came out with
                    # pass@5 exactly equal to pass@1, on all five suites.
                    # A complete run still beats an incomplete one; among
                    # equals, the newest basename wins.
                    # TIEBREAK, IN ORDER: more recorded attempts, then a
                    # complete run, then the newest basename.
                    #
                    # "Newest" alone is wrong for a pass@k table. The same
                    # (scenario, epoch) exists in both a k=1 and a k=5 run, and
                    # whichever sorted later won. When the k=1 record won, the
                    # episode carried one attempt, pass@5 collapsed onto
                    # pass@1, and every ReAct day-1 cell reported zero lift on
                    # all five suites. Measured: the pooled day-1 ccdc set came
                    # out as 250 episodes of exactly 1 attempt, while
                    # acsac_m2_full_react_day1_k5 alone holds 23 of 241
                    # episodes that fail attempt 1 and pass by attempt 5.
                    #
                    # An episode with more attempts strictly dominates one with
                    # fewer: pass@1 is recoverable from it, the reverse is not.
                    # So attempt count is the first key.
                    prev = source.get(key)
                    if prev is not None:
                        prev_n = source_len.get(key, 0)
                        prev_ok = source_ok.get(key, True)
                        if prev_n > len(outcomes):
                            continue
                        if prev_n == len(outcomes):
                            if prev_ok and not ok:
                                continue
                            if prev_ok == ok and base < prev:
                                continue
                    source[key] = base
                    source_ok[key] = ok
                    source_len[key] = len(outcomes)
                    episodes[key] = outcomes
                    # Tokens are summed from the SAME deduplicated episodes as
                    # the accuracies, so tokens-per-success is derivable from
                    # this table instead of being carried over from a different
                    # run set. The published cost table implied a 9x spread in
                    # price per million tokens across rows of one API model,
                    # which is what a mismatched denominator looks like.
                    tok = 0
                    for _mu in (getattr(s, "model_usage", None) or {}).values():
                        tok += getattr(_mu, "total_tokens", 0) or 0
                    tokens[key] = tok
    return episodes, tokens, files, len(seen)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv")
    a = ap.parse_args()

    episodes, tokens, files, uniq = load()
    print(f"loaded {files} log files ({uniq} unique basenames), "
          f"{len(episodes)} deduplicated episodes\n")
    if not episodes:
        print("NO EPISODES MATCHED. Check ROOTS and the solver/model filters.")
        return 1

    cells = defaultdict(list)
    tok_of = defaultdict(int)
    scen_of = defaultdict(set)
    eps_of = defaultdict(set)
    for (model, solver, mode, suite, scen, ep), outcomes in episodes.items():
        cells[(model, solver, mode, suite)].append(outcomes)
        scen_of[(model, solver, mode, suite)].add(scen)
        eps_of[(model, solver, mode, suite)].add(ep)
        tok_of[(model, solver, mode, suite)] += tokens.get(
            (model, solver, mode, suite, scen, ep), 0)

    rows = []
    for key in sorted(cells):
        model, solver, mode, suite = key
        obs = cells[key]
        n = len(obs)
        p1 = [_prefix_pass_at(o, 1, "fail") for o in obs]
        p5 = [_prefix_pass_at(o, 5, "fail") for o in obs]
        p1 = [x for x in p1 if x is not None]
        p5 = [x for x in p5 if x is not None]
        if not p1 or not p5:
            continue
        a1, a5 = 100 * _mean(p1), 100 * _mean(p5)
        lo, hi = wilson(round(_mean(p5) * len(p5)), len(p5))
        rows.append(dict(model=model, solver=solver, condition=mode,
                         suite=suite, n=n,
                         n_scenarios=len(scen_of[key]),
                         n_epochs=len(eps_of[key]),
                         tokens=tok_of[key],
                         tok_per_success=(round(tok_of[key] / (sum(p1)))
                                          if sum(p1) else None),
                         pass1=round(a1, 1),
                         pass5=round(a5, 1), ci_lo=round(lo, 1),
                         ci_hi=round(hi, 1), monotone=(a5 >= a1 - 1e-9)))

    print(f"{'model':<14}{'solver':<16}{'cond':<10}{'suite':<14}"
          f"{'n':>5}{'pass@1':>9}{'pass@5':>9}{'95% CI on @5':>18}  mono")
    for r in rows:
        ci = f"[{r['ci_lo']:.1f}, {r['ci_hi']:.1f}]"
        flag = "ok" if r["monotone"] else "VIOLATION"
        print(f"{r['model']:<14}{r['solver']:<16}{r['condition']:<10}"
              f"{str(r['suite']):<14}{r['n']:>5}{r['pass1']:>8.1f}%"
              f"{r['pass5']:>8.1f}%{ci:>18}  {flag}")

    bad = [r for r in rows if not r["monotone"]]
    print(f"\ncells: {len(rows)}   monotonicity violations: {len(bad)}")
    if bad:
        print("A violation here means the fold is still mixing run sets. "
              "It must be zero before any of this reaches the paper.")

    if a.csv:
        with open(a.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        print(f"wrote {a.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
