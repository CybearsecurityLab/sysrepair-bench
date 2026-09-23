"""tab:cost on the episode set every other exhibit uses (episode_rule, ReAct).
Per kept episode: tokens = input + output summed over model_usage (cache reads
excluded), working_time from the sample, PFLOP = 2 * N_active * tokens.
Mean and standard error over episodes, per model and condition."""
import os, sys, json, glob, zipfile, math, statistics as st
from collections import defaultdict
S = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, S)
import episode_rule
ACTIVE = {"deepseek-v4-flash": 13e9, "minimax-m3": 23e9, "minimax-m2.7": 10e9, "qwen3.5-4b": 4e9,
          "qwen3.5-9b": 9e9, "qwen3.5-27b": 27e9, "qwen3.5-35b": 3e9, "qwen3.5-122b": 10e9}
eps = episode_rule.load()
want = defaultdict(set)
for k, v in eps.items():
    if k[0] in ACTIVE: want[v[0]].add((k[3], k[4], k[0], k[2]))
root = "/home/resbears/projects/sysrepair-bench/inspect_eval"
paths = {}
for f in glob.glob(root + "/logs*/**/*.eval", recursive=True) + glob.glob(root + "/peer_handoff_20260907/**/*.eval", recursive=True):
    b = os.path.basename(f)
    if b in want: paths.setdefault(b, []).append(f)
vals = defaultdict(lambda: defaultdict(list)); missing = 0
for base, keys in want.items():
    fs = sorted(paths.get(base, []), key=lambda p: ("logs_backup" in p or "quarantine" in p, p))
    got = set()
    for f in fs:
        try: z = zipfile.ZipFile(f)
        except Exception: continue
        for nm in z.namelist():
            if not nm.startswith("samples/"): continue
            s = json.loads(z.read(nm))
            sid = s.get("id"); ep = s.get("epoch")
            hit = [k for k in keys if k[0] == sid and k[1] == ep and (sid, ep) not in got]
            if not hit: continue
            got.add((sid, ep)); _, _, m, mo = hit[0]
            tok = sum((u.get("input_tokens") or 0) + (u.get("output_tokens") or 0)
                      for u in (s.get("model_usage") or {}).values() if isinstance(u, dict))
            vals[(m, mo)]["tok"].append(tok); vals[(m, mo)]["s"].append(s.get("working_time") or 0.0)
        if len(got) == len(keys): break
    missing += len(keys) - len(got)
def ms(x): return st.mean(x), (st.stdev(x) / math.sqrt(len(x)) if len(x) > 1 else 0.0)
out = {}
for (m, mo), d in sorted(vals.items()):
    t, te = ms(d["tok"]); w, we = ms(d["s"])
    out[f"{m}|{mo}"] = dict(n=len(d["tok"]), ktok=t / 1e3, ktok_se=te / 1e3, pflop=2 * ACTIVE[m] * t / 1e15,
                            pflop_se=2 * ACTIVE[m] * te / 1e15, s=w, s_se=we)
    print(f"{m:<18}{mo:<9} n={len(d['tok']):5d} ktok {t/1e3:8.0f}±{te/1e3:4.0f}  PFLOP {2*ACTIVE[m]*t/1e15:6.2f}  s {w:6.0f}±{we:3.0f}")
print("episodes not found in any log file:", missing)
json.dump(out, open(os.path.join(S, "cost_rule.json"), "w"), indent=1)
