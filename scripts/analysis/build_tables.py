"""Compute every results exhibit from the cached episodes, on one basis."""
import json, os, sys, random, statistics as st
from collections import defaultdict
S=os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0,"/home/resbears/projects/sysrepair-bench/inspect_eval")
from sysrepair_bench.passk import _prefix_pass_at

MODELS=[("deepseek-v4-flash","DeepSeek-V4-Flash"),("minimax-m3","MiniMax-M3"),
        ("minimax-m2.7","MiniMax-M2.7"),("qwen3.5-4b","Qwen3.5-4B"),
        ("qwen3.5-9b","Qwen3.5-9B"),("qwen3.5-27b","Qwen3.5-27B"),
        ("qwen3.5-35b","Qwen3.5-35B"),("qwen3.5-122b","Qwen3.5-122B")]
SUITES=[("meta2","meta2"),("vulnhub","vulnhub"),("ccdc","ccdc"),
        ("ubuntu","meta3-ub"),("meta4","sr-modern")]

eps={}
for line in open(os.path.join(S,"eps_raw.jsonl")):
    base,model,scaf,mode,sid,ep,outs,sec,reg,bm=json.loads(line)
    if scaf!="react": continue
    k=(model,mode,sid,ep)
    if k not in eps or base>eps[k][0]: eps[k]=(base,outs,sec,reg,bm)
print(f"episodes (react): {len(eps)}", file=sys.stderr)

def scen_map(model,mode,suite=None):
    d=defaultdict(list)
    for (m,mo,sid,_e),(_b,outs,_s,_r,bm) in eps.items():
        if m!=model or mo!=mode: continue
        if suite and bm!=suite: continue
        d[sid].append(outs)
    return d

def passk(d,k):
    if not d: return None
    per=[sum(_prefix_pass_at(o,k) for o in v)/len(v) for v in d.values()]
    return 100*sum(per)/len(per)

def boot(d,k,B=5000,seed=0):
    ids=list(d); 
    if not ids: return None
    per={s:sum(_prefix_pass_at(o,k) for o in d[s])/len(d[s]) for s in ids}
    rnd=random.Random(seed); n=len(ids); vals=[]
    for _ in range(B):
        vals.append(100*sum(per[ids[rnd.randrange(n)]] for _ in range(n))/n)
    vals.sort(); return vals[int(.025*B)], vals[int(.975*B)]

out={}
# tab:results-full  (per suite, pass@5)
grid={}
for mk,mn in MODELS:
    row={}
    for sk,sn in SUITES:
        row[sn]=(passk(scen_map(mk,"day1",sk),5), passk(scen_map(mk,"zero_day",sk),5))
    grid[mn]=row
out["grid"]=grid
# tab:main (benchmark-wide pass@1..5 + CI on @5)
main={}
for mk,mn in MODELS:
    for mo,lab in (("day1","report"),("zero_day","discovery-required")):
        d=scen_map(mk,mo)
        if not d: continue
        main[f"{mn}|{lab}"]=dict(S=len(d), **{f"@{k}":round(passk(d,k),1) for k in range(1,6)},
                                 ci=[round(x,1) for x in boot(d,5)])
out["main"]=main
# tab:taxonomy (failed episodes)
tax={}
for mk,mn in MODELS:
    for mo,lab in (("day1","RI"),("zero_day","DR")):
        c=[0,0,0,0]
        for (m,mm,_s,_e),(_b,_o,sec,reg,_bm) in eps.items():
            if m!=mk or mm!=mo or sec is None or reg is None: continue
            if sec and reg: continue
            c[0]+=1
            if sec and not reg: c[1]+=1
            elif (not sec) and reg: c[2]+=1
            else: c[3]+=1
        if c[0]: tax[f"{mn}|{lab}"]=dict(n=c[0], collateral=round(100*c[1]/c[0],1),
                                         not_remediated=round(100*c[2]/c[0],1), both=round(100*c[3]/c[0],1))
out["taxonomy"]=tax
# tab:paired-gap (scenarios scored in BOTH conditions)
paired={}
for mk,mn in MODELS:
    ri=scen_map(mk,"day1"); dr=scen_map(mk,"zero_day")
    both=sorted(set(ri)&set(dr))
    if len(both)<30: continue
    r={s:sum(_prefix_pass_at(o,5) for o in ri[s])/len(ri[s]) for s in both}
    v={s:sum(_prefix_pass_at(o,5) for o in dr[s])/len(dr[s]) for s in both}
    gap=100*(sum(r.values())-sum(v.values()))/len(both)
    rnd=random.Random(1); n=len(both); B=5000; gs=[]; nonpos=0
    for _ in range(B):
        idx=[both[rnd.randrange(n)] for _ in range(n)]
        g=100*(sum(r[i] for i in idx)-sum(v[i] for i in idx))/n
        gs.append(g)
        if g<=0: nonpos+=1
    gs.sort()
    paired[mn]=dict(n=n, RI=round(100*sum(r.values())/n,1), DR=round(100*sum(v.values())/n,1),
                    gap=round(gap,1), ci=[round(gs[int(.025*B)],1), round(gs[int(.975*B)],1)],
                    nonpos=nonpos)
out["paired"]=paired
json.dump(out, open(os.path.join(S,"tables.json"),"w"), indent=1)

print("\n== tab:results-full (RI/DR pass@5)")
for mn,row in grid.items():
    print(f"{mn:<18}"+" ".join(f"{(row[s][0] or 0):.1f}/{(row[s][1] or 0):.1f}".rjust(12) for _,s in SUITES))
print("\n== tab:main")
for k,v in main.items():
    print(f"{k:<40} S={v['S']:4d} "+" ".join(f"@{j}={v[f'@{j}']:5.1f}" for j in range(1,6))+f" CI={v['ci']}")
print("\n== tab:taxonomy")
for k,v in tax.items(): print(f"{k:<26} n={v['n']:5d} coll={v['collateral']:5.1f} notrem={v['not_remediated']:5.1f} both={v['both']:5.1f}")
print("\n== tab:paired-gap")
for k,v in paired.items(): print(f"{k:<18} n={v['n']:4d} RI={v['RI']:5.1f} DR={v['DR']:5.1f} gap={v['gap']:5.1f} CI={v['ci']} nonpos={v['nonpos']}/5000")
ri=[c[0] for r in grid.values() for c in r.values() if c[0] is not None]
dr=[c[1] for r in grid.values() for c in r.values() if c[1] is not None]
print(f"\nmedians over {len(ri)} RI / {len(dr)} DR cells: RI={st.median(ri):.2f} DR={st.median(dr):.2f}")
