"""Shared log loading for the claim scripts.

One loader so every table in the artifact is built from the same episode set
under the same policies. Divergent ad-hoc loaders are how a corpus ends up with
two tables that disagree about their own denominators.
"""
from __future__ import annotations
import collections
from pathlib import Path

TIER = {"success": 0, "cancelled": 1, "started": 2, "error": 3}

# Errors that mean the harness or the provider failed, not the solver.
_INFRA_ERROR = ("APIConnectionError", "ConnectionError", "RetryError",
                "APITimeoutError", "InternalServerError", "ReadTimeout")


def _infrastructure_error(sample) -> bool:
    """True if this episode ended in a fault outside the solver's control.

    Budget limits are deliberately NOT included: hitting a working_limit is a
    legitimate non-solve under a "repair within budget B" protocol, and dropping
    those would be the biased unresolved="drop" policy.
    """
    err = getattr(sample, "error", None)
    if err is None:
        return False
    text = f"{getattr(err, 'message', '')} {getattr(err, 'traceback', '')} {err}"
    if "sample_limit" in text or "LimitExceeded" in text:
        return False
    return any(k in text for k in _INFRA_ERROR)


def load_episodes(logdir: Path, solver=None, mode=None):
    """{(model, solver, mode, suite, scenario, epoch): sample} across a log tree.

    Deduped on the full key with a status preference, so a scenario re-run in a
    later partial log does not overwrite a completed one. Scenario ids keep
    their suite prefix: `ccdc/scenario-01` and `vulnhub/scenario-01` are
    different scenarios and merging them silently undercounts mixed-suite cells.
    """
    import sysrepair_bench  # noqa: F401
    from inspect_ai.log import list_eval_logs, read_eval_log
    from sysrepair_bench.passk import _is_not_applicable_sample

    best, seen = {}, set()
    for d in [logdir] + [p for p in logdir.rglob("*") if p.is_dir()]:
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
            except Exception:
                continue
            ta = h.eval.task_args or {}
            if solver and ta.get("solver") != solver:
                continue
            if mode and ta.get("mode") != mode:
                continue
            try:
                log = read_eval_log(i.name, header_only=False)
            except Exception:
                continue
            model = str(h.eval.model).split("/")[-1].lower()
            rank = TIER.get(h.status, 9)
            for s in log.samples or []:
                if _is_not_applicable_sample(s):
                    continue
                if _infrastructure_error(s):
                    # An episode whose MODEL CONNECTION died still carries the
                    # attempts it managed before the fault, none of them passing,
                    # so counting it scores an infrastructure failure as a repair
                    # failure. Excluded, and counted separately by the callers.
                    #
                    # This is NOT the unresolved="fail" doctrine being violated.
                    # That doctrine is right because the task is "repair within
                    # budget B", so exhausting the budget is a legitimate
                    # non-solve. Budget is part of the task; the network is not.
                    # There is no protocol under which "the API connection
                    # dropped" is a failure to repair.
                    #
                    # It matters because the rate is CONDITION-CORRELATED:
                    # zero-day episodes are longer and make more model calls, so
                    # they are more exposed. Measured elsewhere in this corpus at
                    # 14 errored zero-day against 3 day-1 on one solver/suite,
                    # which inflates a reported gap rather than adding noise.
                    continue
                meta = s.metadata or {}
                key = (model, ta.get("solver"), ta.get("mode"), meta.get("benchmark"),
                       meta.get("scenario_id") or str(s.id), getattr(s, "epoch", None))
                prev = best.get(key)
                if prev is None or rank < prev[0]:
                    best[key] = (rank, s, ta)
    return {k: (v[1], v[2]) for k, v in best.items()}


def group(episodes, *by):
    """Group loaded episodes by any prefix of the key tuple."""
    idx = {"model": 0, "solver": 1, "mode": 2, "suite": 3, "scenario": 4, "epoch": 5}
    out = collections.defaultdict(list)
    for k, v in episodes.items():
        out[tuple(k[idx[b]] for b in by)].append((k, v))
    return out
