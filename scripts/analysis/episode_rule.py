"""The one episode-inclusion rule every results exhibit uses.

Excluded:
  * episodes that ended in an exception before any verdict (context overflow, rate
    limit, sandbox exception); scoring them as failures instead is reported as a
    sensitivity check;
  * verdicts from the superseded grader (predating the current scorer);
  * a current-format verdict whose per-check lines contradict the recorded verdict;
  * episodes served below the model's declared context (short_ctx.py): a truncated
    context changes which episodes can complete, so they are not a measurement.
Kept as failures:
  * episodes where the grader ran into a dead host and returned a fail with no
    components. An agent that destroys its own host produces exactly these (the
    service-killer adversary does), so they must count.
Kept with components:
  * structured two-component verdicts; current-format verdicts whose summary line
    is missing, with components re-derived from the per-check lines.
Scenarios whose precondition the no-op finds already closed are not-applicable.
Exclusions apply before the cross-root dedup.
"""
import json, os
from collections import defaultdict
S = os.path.dirname(os.path.abspath(__file__))
NA = {"meta4/scenario-36", "meta4/scenario-103"}
EXCLUDE_UNSCORED = {"context-overflow", "rate-limit", "exception", "no-score"}
EXCLUDE_VERDICT = {"superseded", "recoverable-mismatch"}


def load(scaffolds=("react",), return_reasons=False, unscored_as_failure=False):
    unscored = {}
    for l in open(os.path.join(S, "unscored.jsonl")):
        d = json.loads(l)
        for r in d["rows"]:
            unscored[(d["base"], r[0], r[1])] = r[2]
    verdict = {}
    for l in open(os.path.join(S, "verdicts.jsonl")):
        d = json.loads(l)
        for r in d["rows"]:
            verdict[(d["base"], r[0], r[1])] = (r[2], r[3], r[4])
    short = {tuple(x) for x in json.load(open(os.path.join(S, "short_ctx.json")))}
    rows = [json.loads(l) for l in open(os.path.join(S, "eps_raw.jsonl"))]
    eps = {}; ranks = {}; reasons = defaultdict(lambda: defaultdict(int))
    for base, model, scaf, mode, sid, ep, outs, sec, reg, bm in rows:
        if scaf not in scaffolds or sid in NA:
            continue
        key = (base, sid, ep)
        why = unscored.get(key) if unscored.get(key) in EXCLUDE_UNSCORED else None
        filler = False
        if why is not None and unscored_as_failure:     # sensitivity check: count it as a failure
            why = None; outs, sec, reg = [False], None, None; filler = True
        if why is None and key in short:                # served below the declared context
            why = "short-context"
        kind, rsec, rreg = verdict.get(key, ("structured", None, None))
        if why is None and kind in EXCLUDE_VERDICT:
            why = kind
        if why is not None:
            reasons[(model, scaf, mode)][why] += 1
            continue
        if kind == "recoverable" and sec is None:
            sec, reg = rsec, rreg
        k = (model, scaf, mode, sid, ep)
        # a rescored failure only fills an episode with no valid record
        rank = (not filler, base)
        if k not in eps or rank > ranks[k]:
            eps[k] = (base, outs, sec, reg, bm); ranks[k] = rank
    return (eps, {k: dict(v) for k, v in reasons.items()}) if return_reasons else eps
