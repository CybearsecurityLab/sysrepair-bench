"""Round-9 extras: exclusion split per cell; 35B paired gap under score-as-failure with CI."""
import json, os, sys, random, statistics as st
from collections import defaultdict
S = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "/home/resbears/projects/sysrepair-bench/inspect_eval")
from sysrepair_bench.passk import _prefix_pass_at
sys.path.insert(0, S)
import episode_rule
_, reasons = episode_rule.load(return_reasons=True)
for k, v in sorted(reasons.items()):
    nov = sum(n for r, n in v.items() if r in episode_rule.EXCLUDE_UNSCORED)
    print(k[0], k[2], "no-verdict", nov, "predecessor", v.get("superseded", 0), "mismatch", v.get("recoverable-mismatch", 0), dict(v))
fl = episode_rule.load(unscored_as_failure=True)
def per(mode):
    d = defaultdict(list)
    for k, v in fl.items():
        if k[0] == "qwen3.5-35b" and k[2] == mode: d[k[3]].append(_prefix_pass_at(v[1], 5))
    return {s: sum(x) / len(x) for s, x in d.items()}
ri, dr = per("day1"), per("zero_day"); both = sorted(set(ri) & set(dr))
g = defaultdict(list)
for s in both: g[s.split("/")[0]].append(s)
rnd = random.Random(1); gs = []
for _ in range(5000):
    t = 0.0
    for L in g.values():
        for _ in L: s = L[rnd.randrange(len(L))]; t += ri[s] - dr[s]
    gs.append(100 * t / len(both))
gs.sort()
print("35B fail-scored paired gap", round(100 * st.mean(ri[s] - dr[s] for s in both), 1), "n", len(both), "CI", round(gs[125], 1), round(gs[4875], 1))
