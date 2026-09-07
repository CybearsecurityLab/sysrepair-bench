#!/bin/bash
cd /home/resbears/projects/sysrepair-bench/inspect_eval
set -a; . ./.env >/dev/null 2>&1; set +a
echo "[122b-launcher] waiting for :8100 health..."
for i in $(seq 1 180); do
  if curl -s --max-time 4 http://localhost:8100/health >/dev/null 2>&1; then
    echo "[122b-launcher] vLLM healthy after ~$((i*20))s; launching eval"
    uv run python -m sysrepair_bench.run panel_b_qwen_122b_a10b \
      --runs panelB/cascade_panel_b_qwen_122b_a10b.runs.yaml \
      > panelB/run_panel_b_qwen_122b_a10b.log 2>&1
    echo "[122b-launcher] eval exited rc=$?"
    exit 0
  fi
  sleep 20
done
echo "[122b-launcher] TIMEOUT waiting for health (60min)"
