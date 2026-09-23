"""Round-8 analyses, all from the logs.

(1) Sensitivity: score episodes that ended before any verdict as failures,
    instead of excluding them, and recompute pass@5, S and the paired gap.
(2) CDR without the 20 scenarios whose regression probe fails on an untouched host.
(3) Scaffold CDR on scenarios shared by all four scaffolds, with intervals.
(4) Minimum detectable difference per model for the CVE-year split.
(5) Precision-audit error rates with Wilson intervals.
"""
import json, os, re, sys, math, random, statistics as st
from collections import defaultdict
S = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "/home/resbears/projects/sysrepair-bench/inspect_eval")
from sysrepair_bench.passk import _prefix_pass_at

NA = {"meta4/scenario-36", "meta4/scenario-103"}
MODELS = [("deepseek-v4-flash", "DeepSeek-V4-Flash"), ("minimax-m3", "MiniMax-M3"),
          ("minimax-m2.7", "MiniMax-M2.7"), ("qwen3.5-4b", "Qwen3.5-4B"),
          ("qwen3.5-9b", "Qwen3.5-9B"), ("qwen3.5-27b", "Qwen3.5-27B"),
          ("qwen3.5-35b", "Qwen3.5-35B"), ("qwen3.5-122b", "Qwen3.5-122B")]
UNHEALTHY = {"meta4/scenario-100", "meta4/scenario-23", "meta4/scenario-26", "meta4/scenario-53",
             "meta4/scenario-75", "meta4/scenario-76", "meta4/scenario-77", "meta4/scenario-78",
             "meta4/scenario-79", "meta4/scenario-86", "ubuntu/scenario-05", "ubuntu/scenario-06",
             "ubuntu/scenario-09", "ubuntu/scenario-10", "ubuntu/scenario-13", "ubuntu/scenario-16",
             "ubuntu/scenario-17", "ubuntu/scenario-18", "ubuntu/scenario-19", "vulnhub/scenario-05"}
bad = {}
for line in open(os.path.join(S, "unscored.jsonl")):
    d = json.loads(line)
    for r in d["rows"]:
        bad[(d["base"], r[0], r[1])] = r[2]
raw = [json.loads(l) for l in open(os.path.join(S, "eps_raw.jsonl"))]


sys.path.insert(0, S)
import episode_rule
ALL = ("basic", "react", "reflexion", "plan_and_solve")
def build(mode_excl):
    return episode_rule.load(scaffolds=ALL, unscored_as_failure=(mode_excl == "fail"))


def per_scen(eps, model, mode, scaf="react", k=5, keep=None):
    d = defaultdict(list)
    for key, v in eps.items():
        if key[0] == model and key[1] == scaf and key[2] == mode and (keep is None or key[3] in keep):
            d[key[3]].append(_prefix_pass_at(v[1], k))
    return {s: sum(x) / len(x) for s, x in d.items()}


def cdr(eps, model, mode, scaf="react", drop=frozenset(), keep=None, B=5000, seed=0):
    by = defaultdict(lambda: [0, 0])
    for key, v in eps.items():
        if key[0] != model or key[1] != scaf or key[2] != mode or key[3] in drop: continue
        if keep is not None and key[3] not in keep: continue
        if v[2] is None or v[3] is None or not v[2]: continue
        by[key[3]][0] += 1; by[key[3]][1] += (not v[3])
    ns = sum(x[0] for x in by.values()); c = sum(x[1] for x in by.values())
    if not ns: return None
    g = defaultdict(list)
    for s in by: g[s.split("/")[0]].append(s)
    rnd = random.Random(seed); vals = []
    for _ in range(B):
        a = cc = 0
        for L in g.values():
            for _ in L:
                x = by[L[rnd.randrange(len(L))]]; a += x[0]; cc += x[1]
        vals.append(100 * cc / a if a else 0)
    vals.sort()
    return dict(n_s=ns, coll=c, cdr=100 * c / ns, ci=(vals[int(.025 * B)], vals[int(.975 * B)]), S=len(by))


ex = build("exclude"); fl = build("fail")
print("== (1) sensitivity: excluded episodes scored as failures")
print(f"{'model':<18}{'cond':<9}{'S excl':>7}{'@5 excl':>9}{'S fail':>7}{'@5 fail':>9}")
sens = {}
for mk, mn in MODELS:
    for mo in ("day1", "zero_day"):
        a = per_scen(ex, mk, mo); b = per_scen(fl, mk, mo)
        sens[f"{mn}|{mo}"] = dict(S_ex=len(a), p_ex=100 * st.mean(a.values()), S_fail=len(b), p_fail=100 * st.mean(b.values()))
        v = sens[f"{mn}|{mo}"]
        flag = "  <--" if abs(v["p_ex"] - v["p_fail"]) >= 1 else ""
        print(f"{mn:<18}{mo:<9}{v['S_ex']:>7}{v['p_ex']:>9.1f}{v['S_fail']:>7}{v['p_fail']:>9.1f}{flag}")
print("paired gap, excluded as failures:")
gaps = {}
for mk, mn in MODELS:
    ri = per_scen(fl, mk, "day1"); dr = per_scen(fl, mk, "zero_day"); both = set(ri) & set(dr)
    gaps[mn] = 100 * st.mean(ri[s] - dr[s] for s in both)
print({k: round(v, 1) for k, v in gaps.items()}, "median", round(st.median(gaps.values()), 2))

print("\n== (2) CDR without the 20 unhealthy-fixture scenarios")
for mk, mn in MODELS:
    for mo in ("day1", "zero_day"):
        full = cdr(ex, mk, mo); red = cdr(ex, mk, mo, drop=UNHEALTHY)
        share = 100 * (full["coll"] - red["coll"]) / full["coll"] if full["coll"] else 0
        print(f"{mn:<18}{mo:<9} all {full['cdr']:5.1f}  without {red['cdr']:5.1f} [{red['ci'][0]:.1f},{red['ci'][1]:.1f}]  collateral on those 20: {full['coll']-red['coll']}/{full['coll']}")

print("\n== (3) scaffold CDR on scenarios shared by all four scaffolds (report-informed)")
for mk, mn in (("minimax-m2.7", "MiniMax-M2.7"), ("qwen3.5-9b", "Qwen3.5-9B"), ("qwen3.5-35b", "Qwen3.5-35B")):
    sets = []
    for sc in ("basic", "reflexion", "react", "plan_and_solve"):
        sets.append({k[3] for k in ex if k[0] == mk and k[1] == sc and k[2] == "day1"})
    shared = set.intersection(*sets)
    print(f"{mn}: shared scenarios {len(shared)}")
    for sc in ("basic", "reflexion", "react", "plan_and_solve"):
        c = cdr(ex, mk, "day1", scaf=sc, keep=shared)
        if c: print(f"   {sc:<15} n_s={c['n_s']:4d} coll={c['coll']:3d} CDR={c['cdr']:5.1f} CI=[{c['ci'][0]:.1f},{c['ci'][1]:.1f}]")

print("\n== (4) minimum detectable difference per model, CVE-year split (80% power, two-sided 0.05)")
T = json.load(open(os.path.join(S, "tables_v3.json")))
for mn in [m for _, m in MODELS]:
    v = T["contam"].get(f"{mn}|zero_day")
    if not v: continue
    p = (v["pre"] * v["npre"] + v["post"] * v["npost"]) / (v["npre"] + v["npost"]) / 100
    mde = 2.8 * math.sqrt(p * (1 - p) * (1 / v["npre"] + 1 / v["npost"])) * 100
    print(f"  {mn:<18} p={p:.2f} n={v['npre']}/{v['npost']}  MDE={mde:.1f}")

def wilson(k, n, z=1.96):
    ph = k / n; d = 1 + z * z / n; c = (ph + z * z / (2 * n)) / d; h = z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n)) / d
    return 100 * max(0, c - h), 100 * min(1, c + h)
print("\n== (5) precision audit rates")
print(f"  false reject 1/48 = {100/48:.1f}%  Wilson 95% {wilson(1,48)[0]:.1f}-{wilson(1,48)[1]:.1f}")
print(f"  false accept 1/52 = {100/52:.1f}%  Wilson 95% {wilson(1,52)[0]:.1f}-{wilson(1,52)[1]:.1f}")
json.dump(dict(sens=sens, gaps_fail=gaps), open(os.path.join(S, "sensitivity.json"), "w"), indent=1)
