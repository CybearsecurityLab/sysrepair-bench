"""Per-sample serving evidence for locally served Qwen3.5 models: started/completed
time, max single-call input tokens, and any 'maximum context length is N' error.
Output: ctx_timeline.jsonl (one row per sample per file)."""
import os, json, re, glob, zipfile
S = os.path.dirname(os.path.abspath(__file__))
root = "/home/resbears/projects/sysrepair-bench/inspect_eval"
PAT = re.compile(r"maximum context length is (\d+)")
bases = {}
for l in open(os.path.join(S, "eps_raw.jsonl")):
    r = json.loads(l)
    if r[1].startswith("qwen3.5"): bases[r[0]] = r[1]
files = [f for f in glob.glob(root + "/logs*/**/*.eval", recursive=True) if os.path.basename(f) in bases]
out = open(os.path.join(S, "ctx_timeline.jsonl"), "w")
for f in sorted(files):
    try: z = zipfile.ZipFile(f)
    except Exception: continue
    for nm in z.namelist():
        if not nm.startswith("samples/"): continue
        try: s = json.loads(z.read(nm))
        except Exception: continue
        mx = 0; txt = json.dumps(s.get("error") or "")
        for ev in s.get("events", []):
            if ev.get("event") == "model":
                u = (ev.get("output") or {}).get("usage") or {}
                mx = max(mx, u.get("input_tokens") or 0)
                if ev.get("error"): txt += json.dumps(ev["error"])
        lim = PAT.findall(txt)
        out.write(json.dumps([os.path.basename(f), f.replace(root + "/", ""), bases[os.path.basename(f)],
                              s.get("id"), s.get("epoch"), s.get("started_at"), s.get("completed_at"), mx,
                              int(lim[0]) if lim else None]) + "\n")
    out.flush()
out.close(); print("DONE")
