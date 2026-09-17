"""Regenerate CDR denominators from EVERY log root.

Rules enforced:
  - quarantine excluded
  - dedup across roots on BASENAME (full-path sort orders by root prefix, not time)
  - per-episode dedup on (model, mode, scenario, epoch), keep latest basename
  - CDR is EPISODE level, per cdr.py: one sample = one episode, final score
  - skip not_applicable and regression_pass is None (no regression check)
"""
import os, sys, json, re
from collections import defaultdict
import sysrepair_bench  # noqa
from inspect_ai.log import read_eval_log_sample_summaries, read_eval_log

ROOTS = ["inspect_eval/logs_es","inspect_eval/peer_handoff_20260907","inspect_eval/logs_backup",
         "logs","inspect_eval/logs","RECOVERED_minimax_baseline","RECOVERED_baselines",
         "BACKUP_m3_zd_20260831","BACKUP_35b_day1_0111","inspect_eval/logs-validity"]
by_base={}
for r in ROOTS:
    for dp,_,fns in os.walk(r):
        if "quarantine" in dp: continue
        for fn in fns:
            if fn.endswith(".eval"):
                by_base.setdefault(fn, os.path.join(dp,fn))
print(f"unique .eval by basename: {len(by_base)}", file=sys.stderr)

eps={}; bad=0; statuses=defaultdict(int)
BM=defaultdict(int)
SKIP={"hivestorm","windows","meta4/ad-vm"}
for n,(base,path) in enumerate(sorted(by_base.items()),1):
    try:
        h=read_eval_log(path, header_only=True)
    except Exception:
        bad+=1; continue
    statuses[h.status]+=1
    model=(h.eval.model or "?").split("/")[-1].lower()
    model=re.sub(r"-a[0-9]+b$","",model)   # 35b-a3b and 122b-a10b are the same rungs
    ta=h.eval.task_args or {}
    mode=ta.get("mode","day1")
    scaffold=ta.get("scaffold") or ta.get("agent") or ta.get("solver") or "react"
    if scaffold != "react": continue   # the main grid is ReAct throughout
    try:
        summ=read_eval_log_sample_summaries(path)
    except Exception:
        bad+=1; continue
    for s in summ:
        sc=s.scores or {}
        if not sc: continue
        v=list(sc.values())[-1]; md=getattr(v,"metadata",None) or {}
        if md.get("not_applicable") is True or getattr(v,"value",None)=="N": continue
        if "security_pass" not in md or md.get("regression_pass") is None: continue
        bm=(s.metadata or {}).get("benchmark") or str(s.id).split("/")[0]
        BM[bm]+=1
        if bm in SKIP: continue
        k=(model,mode,str(s.id),s.epoch)
        if k not in eps or base > eps[k][0]:
            eps[k]=(base, bool(md["security_pass"]),
                    bool(md["security_pass"]) and bool(md["regression_pass"]))
    if n%50==0: print(f"  {n}/{len(by_base)}", file=sys.stderr)

print("benchmarks seen:", dict(BM), file=sys.stderr)
print(f"unreadable: {bad}  statuses: {dict(statuses)}", file=sys.stderr)
agg=defaultdict(lambda:[0,0,0,set(),set()])
for (m,mo,sid,ep),(_b,sec,joint) in eps.items():
    a=agg[(m,mo)]; a[0]+=sec; a[1]+=joint; a[2]+=1; a[3].add(sid); a[4].add(ep)
rows=[]
for k in sorted(agg):
    sec,joint,n,sids,epn=agg[k]
    rows.append(dict(model=k[0],mode=k[1],episodes=n,scenarios=len(sids),
                     max_epoch=max(epn) if epn else 0,n_s=sec,joint=joint,
                     cdr=None if not sec else round(100*(sec-joint)/sec,1)))
json.dump(rows, open("/tmp/claude-1000/-home-resbears-projects-sysrepair-bench/2b197629-f832-46be-b9e0-d22418033f6b/scratchpad/cdr_regen.json","w"), indent=1)
for r in rows:
    print(f"{r['model']:<22}{r['mode']:<12} episodes={r['episodes']:5d} scen={r['scenarios']:4d} "
          f"maxE={r['max_epoch']:2d} n_s={r['n_s']:5d} CDR={r['cdr']}")
