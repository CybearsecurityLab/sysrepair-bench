"""Read every log once, stream per-episode records to JSONL.

Batch reader (read_eval_log) because the streaming sample reader is ~10x slower.
Records go to disk and the transcript is freed each iteration, so memory stays
bounded. Resumable: skips any log basename already present in the output.
"""
import os, re, json, sys, gc
import sysrepair_bench  # noqa
from inspect_ai.log import read_eval_log
from sysrepair_bench.passk import _attempt_outcomes, _final_score, _is_not_applicable_sample

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "eps_raw.jsonl")
ROOTS = ["inspect_eval/logs_es","inspect_eval/peer_handoff_20260907","inspect_eval/logs_backup",
         "logs","inspect_eval/logs","RECOVERED_minimax_baseline","RECOVERED_baselines",
         "BACKUP_m3_zd_20260831","BACKUP_35b_day1_0111","inspect_eval/logs-validity"]
SKIP = {"hivestorm","windows","meta4/ad-vm","scratchpad"}
# kernel-level CVEs: a container shares the host kernel, so these are graded on
# meta4/kernel-vm and meta4/dirtypipe-vm, never in the container track.
SKIP_IDS = {"meta4/scenario-19","meta4/scenario-21","meta4/scenario-22","meta4/scenario-117"}

by_base = {}
for r in ROOTS:
    for dp,_,fns in os.walk(r):
        if "quarantine" in dp: continue
        for fn in fns:
            if fn.endswith(".eval"): by_base.setdefault(fn, os.path.join(dp,fn))

done = set()
if os.path.exists(OUT):
    for line in open(OUT):
        try: done.add(json.loads(line)[0])
        except Exception: pass
print(f"{len(by_base)} logs, {len(done)} already cached", file=sys.stderr, flush=True)

n = 0
with open(OUT, "a") as fh:
    for i,(base,path) in enumerate(sorted(by_base.items()), 1):
        if base in done: continue
        try: log = read_eval_log(path)
        except Exception: continue
        ta = log.eval.task_args or {}
        scaf = ta.get("scaffold") or ta.get("agent") or ta.get("solver") or "react"
        model = re.sub(r"-a[0-9]+b$","",(log.eval.model or "?").split("/")[-1].lower())
        mode = ta.get("mode","day1")
        for s in (log.samples or []):
            if _is_not_applicable_sample(s): continue
            sid = str(s.id)
            bm = (s.metadata or {}).get("benchmark") or sid.split("/")[0]
            if bm in SKIP or sid in SKIP_IDS: continue
            outs = _attempt_outcomes(s)
            if not outs: continue
            F = _final_score(s); md = (F.metadata or {}) if F is not None else {}
            fh.write(json.dumps([base,model,scaf,mode,sid,s.epoch,outs,
                                 md.get("security_pass"),md.get("regression_pass"),bm])+"\n")
            n += 1
        fh.flush()
        del log; gc.collect()
        if i % 25 == 0: print(f"  {i}/{len(by_base)} new_rows={n}", file=sys.stderr, flush=True)
print(f"DONE new_rows={n}", file=sys.stderr, flush=True)
