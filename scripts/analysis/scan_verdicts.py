"""Per episode: how the grader produced its verdict.
kind: structured | exitcode | recoverable (current-format check lines, summary missing)
      | grader-did-not-run | superseded (no verdict_source: predates the current scorer)
For 'recoverable', security/regression are re-derived from the '[PASS|FAIL] (poc|regression)'
lines exactly as lib/verifylib.sh aggregates them, and validated against the recorded verdict."""
import os, json, zipfile, re
S=os.path.dirname(os.path.abspath(__file__)); OUT=os.path.join(S,"verdicts.jsonl")
LINE=re.compile(r"^\s*\[(PASS|FAIL)\] \((poc|regression)\) ",re.M)
want=set()
for l in open(os.path.join(S,"eps_raw.jsonl")):
    r=json.loads(l)
    if r[2]=="react": want.add(r[0])
ROOTS=["inspect_eval/logs_es","inspect_eval/peer_handoff_20260907","inspect_eval/logs_backup","logs","inspect_eval/logs",
       "RECOVERED_minimax_baseline","RECOVERED_baselines","BACKUP_m3_zd_20260831","BACKUP_35b_day1_0111","inspect_eval/logs-validity"]
path={}
for r in ROOTS:
    for dp,_,fns in os.walk(r):
        if "quarantine" in dp: continue
        for fn in fns:
            if fn in want and fn not in path: path[fn]=os.path.join(dp,fn)
done=set()
if os.path.exists(OUT):
    for l in open(OUT):
        try: done.add(json.loads(l)["base"])
        except Exception: pass
for i,(base,p) in enumerate(sorted(path.items()),1):
    if base in done: continue
    rows=[]
    try:
        z=zipfile.ZipFile(p)
        for n in z.namelist():
            if not (n.startswith("samples/") and n.endswith(".json")): continue
            d=json.loads(z.read(n)); sc=d.get("scores") or {}
            F=sc.get("dispatch_scorer") or sc.get("verify_sh_scorer") or (next(iter(sc.values())) if sc else None)
            if F is None: continue
            md=F.get("metadata") or {}; ex=F.get("explanation") or ""; vs=md.get("verdict_source"); val=F.get("value")
            sec=reg=None
            if md.get("security_pass") is not None: kind="structured"
            elif "verify could not run" in ex or "integrity gate unavailable" in ex or md.get("verify_error"): kind="grader-did-not-run"
            elif vs=="exitcode": kind="exitcode"
            elif LINE.search(ex):
                pc=[m.group(1) for m in LINE.finditer(ex) if m.group(2)=="poc"]
                rg=[m.group(1) for m in LINE.finditer(ex) if m.group(2)=="regression"]
                sec=None if not pc else all(x=="PASS" for x in pc); reg=None if not rg else all(x=="PASS" for x in rg)
                anyfail=("FAIL" in pc) or ("FAIL" in rg)
                kind="recoverable" if (val=="C")==(not anyfail) else "recoverable-mismatch"
            elif vs is None: kind="superseded"
            else: kind="other:"+str(vs)
            rows.append([str(d.get("id")),d.get("epoch"),kind,sec,reg])
    except Exception as e: rows=[["__unreadable__",0,str(e)[:60],None,None]]
    with open(OUT,"a") as fh: fh.write(json.dumps({"base":base,"rows":rows})+"\n")
    if i%25==0: print(i,len(path),flush=True)
print("DONE",flush=True)
