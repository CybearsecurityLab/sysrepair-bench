"""Round-8 data: common-set ladder, per-cell episode bookkeeping, the 35B DR gap,
budget exhaustion, and MiniMax-M2.7's two-component epoch against its grid."""
import json, os, sys, random, statistics as st
from collections import defaultdict, Counter
S = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "/home/resbears/projects/sysrepair-bench/inspect_eval")
from sysrepair_bench.passk import _prefix_pass_at
NA = {"meta4/scenario-36", "meta4/scenario-103"}
MODELS = [("deepseek-v4-flash", "DeepSeek-V4-Flash"), ("minimax-m3", "MiniMax-M3"), ("minimax-m2.7", "MiniMax-M2.7"),
          ("qwen3.5-4b", "Qwen3.5-4B"), ("qwen3.5-9b", "Qwen3.5-9B"), ("qwen3.5-27b", "Qwen3.5-27B"),
          ("qwen3.5-35b", "Qwen3.5-35B"), ("qwen3.5-122b", "Qwen3.5-122B")]
LAD = MODELS[3:]
bad = {}
for l in open(os.path.join(S, "unscored.jsonl")):
    d = json.loads(l)
    for r in d["rows"]: bad[(d["base"], r[0], r[1])] = r[2]
lim = {}
for l in open(os.path.join(S, "limits.jsonl")):
    d = json.loads(l)
    for r in d["rows"]: lim[(d["base"], r[0], r[1])] = (r[2], r[3])
raw = [json.loads(l) for l in open(os.path.join(S, "eps_raw.jsonl"))]
eps = {}; excl = defaultdict(Counter); ran = defaultdict(set)
for base, model, scaf, mode, sid, ep, outs, sec, reg, bm in raw:
    if scaf != "react" or sid in NA: continue
    ran[(model, mode)].add(sid)
    kind = bad.get((base, sid, ep))
    if kind is not None:
        excl[(model, mode)][kind] += 1; continue
    k = (model, mode, sid, ep)
    if k not in eps or base > eps[k][0]: eps[k] = (base, outs, sec, reg, bm)

def per(model, mode, keep=None):
    d = defaultdict(list)
    for k, v in eps.items():
        if k[0] == model and k[1] == mode and (keep is None or k[2] in keep): d[k[2]].append(_prefix_pass_at(v[1], 5))
    return {s: sum(x) / len(x) for s, x in d.items()}

def cdr(model, mode, keep=None):
    ns = c = 0
    for k, v in eps.items():
        if k[0] != model or k[1] != mode or (keep is not None and k[2] not in keep): continue
        if v[2] is None or v[3] is None or not v[2]: continue
        ns += 1; c += (not v[3])
    return 100 * c / ns if ns else None, ns

out = {}
print("== per-cell bookkeeping (ReAct)")
print(f"{'model':<18}{'cond':<9}{'eps kept':>9}{'excluded':>9}{'ctx':>5}{'rate':>5}{'exc':>5}{'S':>5}{'E dist':>28}{'budget-hit':>11}")
for mk, mn in MODELS:
    for mo in ("day1", "zero_day"):
        E = {k: v for k, v in eps.items() if k[0] == mk and k[1] == mo}
        cnt = Counter(Counter(k[2] for k in E).values())
        hit = sum(1 for k, v in E.items() if (lim.get((v[0], k[2], k[3])) or (None,))[0] in ("working", "time"))
        x = excl[(mk, mo)]
        out[f"{mn}|{mo}"] = dict(kept=len(E), excluded=sum(x.values()), ctx=x["context-overflow"], rate=x["rate-limit"],
                                 exc=x["exception"], S=len({k[2] for k in E}), E_dist=dict(sorted(cnt.items())), budget=hit)
        print(f"{mn:<18}{mo:<9}{len(E):>9}{sum(x.values()):>9}{x['context-overflow']:>5}{x['rate-limit']:>5}{x['exception']:>5}"
              f"{len({k[2] for k in E}):>5}{str(dict(sorted(cnt.items()))):>28}{hit:>11}")

missing = sorted(set().union(*[set(per(m, "day1")) for m, _ in LAD]) - set(per("qwen3.5-35b", "zero_day")))
ran35 = ran[("qwen3.5-35b", "zero_day")]
print(f"\n== 35B DR: {len(missing)} scenarios with no surviving episode; by suite:", dict(Counter(s.split('/')[0] for s in missing)))
print("   of these, ran but every episode excluded:", sum(1 for s in missing if s in ran35), "| never ran:", sum(1 for s in missing if s not in ran35))

common = set(per("qwen3.5-35b", "zero_day"))
for mk, _ in LAD:
    common &= set(per(mk, "day1")) & set(per(mk, "zero_day"))
print(f"\n== ladder on the common set ({len(common)} scenarios, all rungs, both conditions)")
lad = {}
for mk, mn in LAD:
    ri = per(mk, "day1", common); dr = per(mk, "zero_day", common)
    gap = 100 * st.mean(ri[s] - dr[s] for s in common)
    c, ns = cdr(mk, "zero_day", common)
    lad[mn] = dict(RI=100 * st.mean(ri.values()), DR=100 * st.mean(dr.values()), gap=gap, cdr_dr=c, ns=ns)
    print(f"  {mn:<14} RI {lad[mn]['RI']:5.1f}  DR {lad[mn]['DR']:5.1f}  gap {gap:5.1f}  DR CDR {c:5.1f} (n_s {ns})")
out["common_n"] = len(common); out["ladder_common"] = lad; out["missing35"] = dict(Counter(s.split('/')[0] for s in missing))

print("\n== MiniMax-M2.7: its two-component epoch against the rest of its grid")
for mo in ("day1", "zero_day"):
    d1 = defaultdict(list); d2 = defaultdict(list)
    for k, v in eps.items():
        if k[0] != "minimax-m2.7" or k[1] != mo: continue
        (d1 if v[2] is not None else d2)[k[2]].append(_prefix_pass_at(v[1], 5))
    shared = set(d1) & set(d2)
    a = 100 * st.mean(sum(d1[s]) / len(d1[s]) for s in shared); b = 100 * st.mean(sum(d2[s]) / len(d2[s]) for s in shared)
    out[f"m27|{mo}"] = dict(two=a, one=b, n=len(shared))
    print(f"  {mo}: on {len(shared)} shared scenarios, pass@5 {a:.1f} (two-component epoch) vs {b:.1f} (single-verdict epochs)")
json.dump(out, open(os.path.join(S, "round8.json"), "w"), indent=1)
