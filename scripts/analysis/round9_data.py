"""Round-9 analyses, all from the logs.
(1) Budget: per-cell budget-exhaustion share; pass@5 and paired gap with
    budget-exhausted episodes censored (dropped) in both conditions.
(2) Paired scenario bootstrap for the CDR comparisons the paper states
    (ladder DR 4B vs 35B, 4B vs 9B; scaffold PS vs ReAct per model).
(3) Accuracy and paired gap without the 20 scenarios whose regression probe
    fails on an untouched host.
"""
import json, os, sys, random, statistics as st
from collections import defaultdict
S = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "/home/resbears/projects/sysrepair-bench/inspect_eval")
from sysrepair_bench.passk import _prefix_pass_at
sys.path.insert(0, S)
import episode_rule
exec(open(os.path.join(S,"sensitivity.py")).read().split("bad = {}")[0])
B = 5000
lim = {}
for l in open(os.path.join(S, "limits.jsonl")):
    d = json.loads(l)
    for r in d["rows"]: lim[(d["base"], r[0], r[1])] = r[2]
ALL = ("basic", "react", "reflexion", "plan_and_solve")
eps = episode_rule.load(scaffolds=ALL)
def hit(k, v): return lim.get((v[0], k[3], k[4])) in ("working", "time")

def per(model, mode, scaf="react", censor=False, drop=frozenset()):
    d = defaultdict(list)
    for k, v in eps.items():
        if k[0] == model and k[1] == scaf and k[2] == mode and k[3] not in drop and not (censor and hit(k, v)):
            d[k[3]].append(_prefix_pass_at(v[1], 5))
    return {s: sum(x) / len(x) for s, x in d.items()}

def strata(ids):
    g = defaultdict(list)
    for s in ids: g[s.split("/")[0]].append(s)
    return g

out = {"budget": {}, "unhealthy": {}, "cdr_pairs": {}}
print("== (1) budget exhaustion and censored gap")
for mk, mn in MODELS:
    row = {}
    for mo in ("day1", "zero_day"):
        E = [(k, v) for k, v in eps.items() if k[0] == mk and k[1] == "react" and k[2] == mo]
        h = sum(hit(k, v) for k, v in E)
        row[mo] = dict(n=len(E), hit=h, share=100 * h / len(E))
    ri, dr = per(mk, "day1", censor=True), per(mk, "zero_day", censor=True)
    both = set(ri) & set(dr)
    row["cens"] = dict(RI=100 * st.mean(ri.values()), DR=100 * st.mean(dr.values()), n=len(both),
                       gap=100 * st.mean(ri[s] - dr[s] for s in both))
    out["budget"][mn] = row
    print(f"{mn:<18} RI hit {row['day1']['hit']}/{row['day1']['n']} ({row['day1']['share']:.0f}%)  DR hit {row['zero_day']['hit']}/{row['zero_day']['n']} ({row['zero_day']['share']:.0f}%)"
          f"  censored: RI {row['cens']['RI']:.1f} DR {row['cens']['DR']:.1f} gap {row['cens']['gap']:.1f} (n {len(both)})")
print("censored median gap", round(st.median(r["cens"]["gap"] for r in out["budget"].values()), 2))

print("\n== (3) without the 20 unhealthy-fixture scenarios")
gaps = {}
for mk, mn in MODELS:
    ri, dr = per(mk, "day1", drop=UNHEALTHY), per(mk, "zero_day", drop=UNHEALTHY)
    both = set(ri) & set(dr)
    gaps[mn] = 100 * st.mean(ri[s] - dr[s] for s in both)
    out["unhealthy"][mn] = dict(RI=100 * st.mean(ri.values()), DR=100 * st.mean(dr.values()), gap=gaps[mn], n=len(both))
    print(f"{mn:<18} RI {out['unhealthy'][mn]['RI']:.1f} DR {out['unhealthy'][mn]['DR']:.1f} gap {gaps[mn]:.1f} (n {len(both)})")
print("median gap", round(st.median(gaps.values()), 2), "range", round(min(gaps.values()), 1), round(max(gaps.values()), 1))

def cdr_by(model, mode, scaf):
    by = defaultdict(lambda: [0, 0])
    for k, v in eps.items():
        if k[0] == model and k[1] == scaf and k[2] == mode and v[2] and v[3] is not None:
            by[k[3]][0] += 1; by[k[3]][1] += (not v[3])
    return by

def paired(a, b, seed=0):
    ids = sorted(set(a) & set(b)); g = strata(ids); rnd = random.Random(seed); vals = []
    def c(by, L): n = sum(by[s][0] for s in L); return 100 * sum(by[s][1] for s in L) / n if n else 0.0
    pt = c(a, ids) - c(b, ids)
    for _ in range(B):
        L = [x for ids_ in g.values() for x in (ids_[rnd.randrange(len(ids_))] for _ in ids_)]
        vals.append(c(a, L) - c(b, L))
    vals.sort(); lo, hi = vals[int(.025 * B)], vals[int(.975 * B)]
    p = 2 * min(sum(v <= 0 for v in vals), sum(v >= 0 for v in vals)) / B
    return dict(n=len(ids), diff=pt, ci=(lo, hi), p=min(1.0, p), a=c(a, ids), b=c(b, ids))

print("\n== (2) paired scenario bootstrap on CDR differences")
pairs = [("ladder DR 4B-35B", ("qwen3.5-4b", "zero_day", "react"), ("qwen3.5-35b", "zero_day", "react")),
         ("ladder DR 4B-9B", ("qwen3.5-4b", "zero_day", "react"), ("qwen3.5-9b", "zero_day", "react")),
         ("ladder DR 35B-122B", ("qwen3.5-122b", "zero_day", "react"), ("qwen3.5-35b", "zero_day", "react")),
         ("ladder RI 4B-9B", ("qwen3.5-4b", "day1", "react"), ("qwen3.5-9b", "day1", "react"))]
for m in ("minimax-m2.7", "qwen3.5-9b", "qwen3.5-35b"):
    pairs.append((f"{m} RI PS-ReAct", (m, "day1", "plan_and_solve"), (m, "day1", "react")))
for mk, _ in MODELS:
    pairs.append((f"{mk} DR-RI", (mk, "zero_day", "react"), (mk, "day1", "react")))
for name, x, y in pairs:
    r = paired(cdr_by(*x), cdr_by(*y)); out["cdr_pairs"][name] = r
    print(f"  {name:<28} n={r['n']:3d}  {r['a']:.1f} vs {r['b']:.1f}  diff {r['diff']:+.1f} [{r['ci'][0]:+.1f},{r['ci'][1]:+.1f}] p={r['p']:.4f}")
json.dump(out, open(os.path.join(S, "round9.json"), "w"), indent=1)

print("\n== ladder DR CDR, 4B against each rung")
for m in ("qwen3.5-9b", "qwen3.5-27b", "qwen3.5-35b", "qwen3.5-122b"):
    r = paired(cdr_by("qwen3.5-4b", "zero_day", "react"), cdr_by(m, "zero_day", "react"))
    out["cdr_pairs"][f"ladder DR 4B-{m}"] = r
    print(f"  4B-{m}: n={r['n']} {r['a']:.1f} vs {r['b']:.1f} diff {r['diff']:+.1f} [{r['ci'][0]:+.1f},{r['ci'][1]:+.1f}] p={r['p']:.4f}")
json.dump(out, open(os.path.join(S, "round9.json"), "w"), indent=1)
