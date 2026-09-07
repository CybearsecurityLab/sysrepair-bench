#!/bin/bash
cd /home/resbears/projects/sysrepair-bench/inspect_eval
set -a; . ./.env >/dev/null 2>&1; set +a
for preset in ccdc_minimax_m3 meta3ubuntu_minimax_m3 hivestorm_minimax_m3 meta4_minimax_m3; do
  echo "[$(date -u +%H:%M:%S)] START $preset"
  uv run python -m sysrepair_bench.run "$preset" > "panelB/run_${preset}.log" 2>&1
  echo "[$(date -u +%H:%M:%S)] DONE $preset rc=$?"
done
echo "[$(date -u +%H:%M:%S)] MINIMAX SUITE CHAIN COMPLETE"
