"""Per episode: whether it hit a harness limit (budget exhaustion), and its working time."""
import os, json, zipfile
S=os.path.dirname(os.path.abspath(__file__)); OUT=os.path.join(S,"limits.jsonl")
want=set()
for line in open(os.path.join(S,"eps_raw.jsonl")):
    r=json.loads(line)
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
            d=json.loads(z.read(n)); lim=d.get("limit")
            rows.append([str(d.get("id")),d.get("epoch"),(lim or {}).get("type") if isinstance(lim,dict) else lim,
                         d.get("working_time"),d.get("total_time")])
    except Exception as e: rows=[["__unreadable__",0,str(e)[:60],None,None]]
    with open(OUT,"a") as fh: fh.write(json.dumps({"base":base,"rows":rows})+"\n")
    if i%25==0: print(i,len(path),flush=True)
print("DONE",flush=True)
