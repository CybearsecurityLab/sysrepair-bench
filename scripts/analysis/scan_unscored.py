"""List episodes that ended without a final score value (the sample raised an
exception before grading). Resumable; one line per log."""
import os, json, zipfile, sys
S=os.path.dirname(os.path.abspath(__file__)); OUT=os.path.join(S,"unscored.jsonl")
ROOTS=["inspect_eval/logs_es","inspect_eval/peer_handoff_20260907","inspect_eval/logs_backup","logs","inspect_eval/logs",
       "RECOVERED_minimax_baseline","RECOVERED_baselines","BACKUP_m3_zd_20260831","BACKUP_35b_day1_0111","inspect_eval/logs-validity"]
by_base={}
for r in ROOTS:
    for dp,_,fns in os.walk(r):
        if "quarantine" in dp: continue
        for fn in fns:
            if fn.endswith(".eval"): by_base.setdefault(fn, os.path.join(dp,fn))
done=set()
if os.path.exists(OUT):
    for l in open(OUT):
        try: done.add(json.loads(l)["base"])
        except Exception: pass
for i,(base,p) in enumerate(sorted(by_base.items()),1):
    if base in done: continue
    rows=[]
    try:
        z=zipfile.ZipFile(p)
        for n in z.namelist():
            if not (n.startswith("samples/") and n.endswith(".json")): continue
            d=json.loads(z.read(n)); sc=d.get("scores") or {}
            F=None
            for key in ("dispatch_scorer","verify_sh_scorer"):
                if key in sc: F=sc[key]; break
            if F is None and sc: F=next(iter(sc.values()))
            val=None if F is None else F.get("value")
            err=((d.get("error") or {}).get("message") or "")
            if val is None or err:
                if "maximum context length" in err: kind="context-overflow"
                elif "RateLimit" in err or " 429" in err: kind="rate-limit"
                elif err: kind="exception"
                else: kind="no-score"
                rows.append([str(d.get("id")),d.get("epoch"),kind,val])
    except Exception as e:
        rows=[["__unreadable__",0,str(e)[:80]]]
    with open(OUT,"a") as fh: fh.write(json.dumps({"base":base,"rows":rows})+"\n")
    if i%25==0: print(i,len(by_base),flush=True)
print("DONE",flush=True)
