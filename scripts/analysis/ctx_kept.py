"""Serving-context evidence for every kept Qwen episode's source log:
dir, kept episodes, max single-call input tokens, overflow limits seen."""
import sys, os, json, re, glob, zipfile
from collections import Counter, defaultdict
S = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, S); import episode_rule
eps = episode_rule.load(scaffolds=("basic", "react", "reflexion", "plan_and_solve"))
kept = defaultdict(Counter)
for k, v in eps.items():
    if k[0].startswith("qwen3.5") and k[0] not in ("qwen3.5-397b",): kept[v[0]][(k[0], k[1], k[2])] += 1
root = "/home/resbears/projects/sysrepair-bench/inspect_eval"
paths = {}
for f in glob.glob(root + "/logs*/**/*.eval", recursive=True):
    paths.setdefault(os.path.basename(f), []).append(f)
PAT = re.compile(r"maximum context length is (\d+)")
out = []
for base, cells in sorted(kept.items()):
    fs = paths.get(base, [])
    f = sorted(fs, key=lambda p: ("logs_backup" in p, p))[0] if fs else None
    mx = 0; lim = Counter(); n = 0
    if f:
        z = zipfile.ZipFile(f)
        for nm in z.namelist():
            if not nm.startswith("samples/"): continue
            s = json.loads(z.read(nm)); n += 1
            txt = json.dumps(s.get("error") or "")
            for ev in s.get("events", []):
                if ev.get("event") == "model":
                    u = (ev.get("output") or {}).get("usage") or {}
                    mx = max(mx, u.get("input_tokens") or 0)
                    e = ev.get("error")
                    if e: txt += json.dumps(e)
            for m in PAT.findall(txt): lim[m] += 1
    row = dict(base=base, dir=(f or "").replace(root + "/", "").rsplit("/", 1)[0], cells={"|".join(c): v for c, v in cells.items()},
               samples=n, max_input=mx, limits=dict(lim))
    out.append(row); print(json.dumps(row), flush=True)
json.dump(out, open(os.path.join(S, "ctx_kept.json"), "w"), indent=1)
print("DONE")
