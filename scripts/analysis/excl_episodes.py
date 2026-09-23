"""Excluded EPISODES per ReAct cell: episode keys with an excluded record and no
kept record (a later valid rerun of the same episode replaces an excluded one)."""
import json, sys, os
from collections import defaultdict, Counter
S = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, S)
import episode_rule as R
unscored = {}; verdict = {}
for l in open(os.path.join(S, "unscored.jsonl")):
    d = json.loads(l)
    for r in d["rows"]: unscored[(d["base"], r[0], r[1])] = r[2]
for l in open(os.path.join(S, "verdicts.jsonl")):
    d = json.loads(l)
    for r in d["rows"]: verdict[(d["base"], r[0], r[1])] = r[2]
eps = R.load()
short = {tuple(x) for x in json.load(open(os.path.join(S, "short_ctx.json")))}
why = defaultdict(set)
for l in open(os.path.join(S, "eps_raw.jsonl")):
    base, model, scaf, mode, sid, ep, *_ = json.loads(l)
    if scaf != "react" or sid in R.NA: continue
    k = (base, sid, ep); u = unscored.get(k); v = verdict.get(k, "structured")
    w = "short-context" if k in short else (u if u in R.EXCLUDE_UNSCORED else (v if v in R.EXCLUDE_VERDICT else None))
    if w: why[(model, mode, sid, ep)].add(w)
out = defaultdict(Counter)
for (m, mo, sid, ep), ws in why.items():
    if (m, "react", mo, sid, ep) in eps: continue
    out[f"{m}|{mo}"]["short" if "short-context" in ws else ("no_verdict" if ws & R.EXCLUDE_UNSCORED else "unusable")] += 1
    for w in ws: out[f"{m}|{mo}"]["r:" + w] += 1
    if m == "qwen3.5-35b" and mo == "zero_day": out["35b_dr_suites"][sid.split("/")[0]] += 1
for k in sorted(out): print(k, dict(out[k]))
json.dump(out, open(os.path.join(S, "excl_episodes.json"), "w"), indent=1)
