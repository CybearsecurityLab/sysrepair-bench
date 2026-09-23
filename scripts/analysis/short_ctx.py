"""Episodes served below the model's declared context (262144), from the per-sample
serving timeline (ctx_timeline.jsonl). The local server ran at 32768 in two windows,
bounded by the last episode exceeding 32k before the first 32768 overflow error and
by the last such error:
  Qwen3.5-35B: episodes started after 2026-09-01T05:46:37Z (no later episode exceeds 32k);
  Qwen3.5-9B:  episodes started 2026-09-06T00:00Z .. 2026-09-07T19:52:21Z on the local
               server (the full-context rerun and the Delta leg are separate servers);
  Qwen3.5-122B: every episode before 2026-09-01, served by launch_122b_gptq.sh at
               --max-model-len 49152 (serve_122b_gptq_fullctx.sh supersedes it)."""
import json, os
S = os.path.dirname(os.path.abspath(__file__))
out = set()
for l in open(os.path.join(S, "ctx_timeline.jsonl")):
    base, path, model, sid, ep, st, ct, mx, lim = json.loads(l)
    if not st: continue
    if model == "qwen3.5-35b" and st > "2026-09-01T05:46:37.1":
        out.add((base, sid, ep))
    if model == "qwen3.5-122b" and st < "2026-09-01":
        out.add((base, sid, ep))
    if (model == "qwen3.5-9b" and "2026-09-06T00:00" <= st <= "2026-09-07T19:52:21"
            and "fullctx" not in path and "delta" not in path):
        out.add((base, sid, ep))
json.dump(sorted(out), open(os.path.join(S, "short_ctx.json"), "w"))
print(len(out), "episodes served below full context")
