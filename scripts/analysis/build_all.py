"""Build every result exhibit from one episode set.

Episode set: the cached ReAct episodes, with two exclusions applied BEFORE the
cross-root dedup (so an excluded rerun cannot displace a valid earlier episode):
  * episodes that ended in an exception before a verdict was recorded
    (unscored.jsonl: harness/sandbox exceptions, context overflow, rate limits);
  * scenarios whose precondition the no-op sweep finds already closed
    (meta4/scenario-36, meta4/scenario-103), treated as not-applicable.
pass@k: prefix estimator per episode, averaged within scenario, then across
scenarios. CDR pool E_c: episodes whose verifier reported both components.
Intervals: scenario bootstrap stratified by suite, 5000 resamples.
"""
import json, os, re, sys, random, statistics as st
from collections import defaultdict
S = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "/home/resbears/projects/sysrepair-bench/inspect_eval")
from sysrepair_bench.passk import _prefix_pass_at

NA = {"meta4/scenario-36", "meta4/scenario-103"}
MODELS = [("deepseek-v4-flash", "DeepSeek-V4-Flash"), ("minimax-m3", "MiniMax-M3"),
          ("minimax-m2.7", "MiniMax-M2.7"), ("qwen3.5-4b", "Qwen3.5-4B"),
          ("qwen3.5-9b", "Qwen3.5-9B"), ("qwen3.5-27b", "Qwen3.5-27B"),
          ("qwen3.5-35b", "Qwen3.5-35B"), ("qwen3.5-122b", "Qwen3.5-122B")]
SUITES = [("meta2", "meta2"), ("vulnhub", "vulnhub"), ("ccdc", "ccdc"),
          ("ubuntu", "meta3-ub"), ("meta4", "sr-modern")]
B = 5000

sys.path.insert(0, S)
import episode_rule
eps, _reasons = episode_rule.load(scaffolds=("basic", "react", "reflexion", "plan_and_solve"), return_reasons=True)
dropped = {k: sum(v.values()) for k, v in _reasons.items()}


def episodes(model, mode, scaf="react", suite=None):
    return {k: v for k, v in eps.items()
            if k[0] == model and k[1] == scaf and k[2] == mode and (suite is None or v[4] == suite)}


def per_scenario(E, k=5):
    d = defaultdict(list)
    for key, v in E.items():
        d[key[3]].append(_prefix_pass_at(v[1], k))
    return {s: sum(x) / len(x) for s, x in d.items()}


def strata(ids):
    g = defaultdict(list)
    for s in ids:
        g[s.split("/")[0]].append(s)
    return g


def boot_mean(per, seed=0):
    g = strata(per); rnd = random.Random(seed); n = len(per); vals = []
    for _ in range(B):
        tot = 0.0
        for su, ids in g.items():
            for _ in ids:
                tot += per[ids[rnd.randrange(len(ids))]]
        vals.append(100 * tot / n)
    vals.sort(); return vals[int(.025 * B)], vals[int(.975 * B)]


def cdr_cell(E, seed=0):
    pool = [(k[3], v) for k, v in E.items() if v[2] is not None and v[3] is not None]
    by = defaultdict(lambda: [0, 0])          # scenario -> [n_s, collateral]
    for s, v in pool:
        if v[2]:
            by[s][0] += 1
            by[s][1] += (not v[3])
    ns = sum(x[0] for x in by.values()); coll = sum(x[1] for x in by.values())
    joint = sum(1 for _, v in pool if v[2] and v[3])
    notrem = sum(1 for _, v in pool if (not v[2]) and v[3])
    both = sum(1 for _, v in pool if (not v[2]) and (not v[3]))
    ci = None
    if ns:
        ids = list(by); g = strata(ids); rnd = random.Random(seed); vals = []
        for _ in range(B):
            a = c = 0
            for su, L in g.items():
                for _ in L:
                    x = by[L[rnd.randrange(len(L))]]; a += x[0]; c += x[1]
            vals.append(100 * c / a if a else 0.0)
        vals.sort(); ci = (vals[int(.025 * B)], vals[int(.975 * B)])
    return dict(episodes=len(E), E_c=len(pool), n_s=ns, cdr=(100 * coll / ns if ns else None),
                ci=ci, failed=len(pool) - joint, coll=coll, notrem=notrem, both=both,
                scenarios=len({k[3] for k in E}))


out = {"grid": {}, "main": {}, "paired": {}, "cdr": {}, "scaffold": {}, "contam": {},
       "dropped": {f"{k[0]}|{k[1]}|{k[2]}": v for k, v in dropped.items()}}
for mk, mn in MODELS:
    out["grid"][mn] = {sn: [100 * st.mean(per_scenario(episodes(mk, mo, suite=sk)).values())
                            if episodes(mk, mo, suite=sk) else None for mo in ("day1", "zero_day")]
                       for sk, sn in SUITES}
    for mo, lab in (("day1", "report"), ("zero_day", "discovery-required")):
        E = episodes(mk, mo)
        if not E:
            continue
        cur = {k: 100 * st.mean(per_scenario(E, k).values()) for k in range(1, 6)}
        per5 = per_scenario(E, 5)
        ep_by = defaultdict(set)
        for key in E: ep_by[key[3]].add(key[4])
        out["main"][f"{mn}|{lab}"] = dict(S=len(per5), **{f"@{k}": cur[k] for k in cur},
                                          ci=boot_mean(per5), maxE=max(len(x) for x in ep_by.values()))
        out["cdr"][f"{mn}|{mo}"] = cdr_cell(E)
    ri = per_scenario(episodes(mk, "day1")); dr = per_scenario(episodes(mk, "zero_day"))
    both = sorted(set(ri) & set(dr))
    if both:
        g = strata(both); rnd = random.Random(1); gs = []; nonpos = 0; n = len(both)
        for _ in range(B):
            tot = 0.0
            for su, L in g.items():
                for _ in L:
                    s = L[rnd.randrange(len(L))]; tot += ri[s] - dr[s]
            v = 100 * tot / n; gs.append(v); nonpos += v <= 0
        gs.sort()
        out["paired"][mn] = dict(n=n, RI=100 * st.mean(ri[s] for s in both), DR=100 * st.mean(dr[s] for s in both),
                                 gap=100 * st.mean(ri[s] - dr[s] for s in both),
                                 ci=(gs[int(.025 * B)], gs[int(.975 * B)]), nonpos=nonpos)
    for scaf in ("basic", "react", "reflexion", "plan_and_solve"):
        c = cdr_cell(episodes(mk, "day1", scaf))
        if c["n_s"] >= 30:
            out["scaffold"][f"{mn}|{scaf}"] = c

# CVE-year split on the dated container-track sr-modern scenarios
KERNEL = {"meta4/scenario-19", "meta4/scenario-21", "meta4/scenario-22", "meta4/scenario-117"}
year = {}
for l in open("/home/resbears/projects/sysrepair-bench/scenarios.jsonl"):
    r = json.loads(l)
    if r["suite"] == "meta4" and r["kind"] == "linux-container" and r["scenario_id"] not in KERNEL | NA:
        ys = [int(m) for c in r["cves"] for m in re.findall(r"CVE-(\d{4})", c)]
        if ys: year[r["scenario_id"]] = min(ys)
out["contam_dated"] = len(year)
for mk, mn in MODELS:
    for mo in ("day1", "zero_day"):
        per = per_scenario(episodes(mk, mo, suite="meta4"))
        pre = [per[s] for s in per if s in year and year[s] < 2023]
        post = [per[s] for s in per if s in year and year[s] >= 2023]
        if pre and post:
            out["contam"][f"{mn}|{mo}"] = dict(pre=100 * st.mean(pre), npre=len(pre), post=100 * st.mean(post), npost=len(post))

json.dump(out, open(os.path.join(S, "tables_v3.json"), "w"), indent=1)
print("episodes kept:", len(eps), "| dropped (exception before verdict), react cells:",
      {k: v for k, v in out["dropped"].items() if "|react|" in k})
