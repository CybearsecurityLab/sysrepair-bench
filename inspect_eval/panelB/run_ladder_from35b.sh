#!/bin/bash
# Continue the Qwen ladder from 35B (4B/9B/27B already complete; the main
# run_ladder.sh was stopped to relaunch a stuck 27B rung). Same cascade logic:
# each rung runs only the scenarios the previous rung failed. prev starts as
# Qwen3.5-27B so 35B scopes to 27B's failures. 397B is on HPC (separate).
set -u
cd /home/resbears/projects/sysrepair-bench/inspect_eval

LADDER=(
  "Qwen/Qwen3.5-35B-A3B:panel_b_qwen_35b_a3b:2:"
  "Qwen/Qwen3.5-122B-A10B:panel_b_qwen_122b_a10b:2:--quantization fp8"
)
prev_model="Qwen/Qwen3.5-27B"

for item in "${LADDER[@]}"; do
  model="${item%%:*}"; rest="${item#*:}"
  preset="${rest%%:*}"; rest="${rest#*:}"; tp="${rest%%:*}"; extra="${rest#*:}"
  echo "===================================================================="
  echo "[$(date -u +%H:%M:%S)] BEGIN $model preset=$preset tp=$tp extra='$extra'"
  runs_arg=()
  echo "[$(date -u +%H:%M:%S)] cascade: scoping $preset to $prev_model failures"
  prev_tag="${prev_model##*/}"
  if uv run python panelB/cascade_prep.py "$prev_tag" "$preset" \
       --out "panelB/cascade_${preset}.runs.yaml" 2> >(tee -a panelB/ladder.log >&2); then
    runs_arg=(--runs "panelB/cascade_${preset}.runs.yaml")
  else
    rc=$?
    if [ "$rc" = 3 ]; then echo "[$(date -u +%H:%M:%S)] $prev_model aced all — SKIP $model"; prev_model="$model"; continue; fi
    echo "[$(date -u +%H:%M:%S)] cascade prep rc=$rc — FULL run for $model"
  fi
  if ! bash panelB/serve.sh "$model" "$tp" $extra; then
    echo "[$(date -u +%H:%M:%S)] SERVE FAILED $model — skip"; bash panelB/stop.sh; prev_model="$model"; continue
  fi
  echo "[$(date -u +%H:%M:%S)] serving OK; launching $preset"
  uv run python -m sysrepair_bench.run "$preset" "${runs_arg[@]}" > "panelB/run_${preset}.log" 2>&1
  echo "[$(date -u +%H:%M:%S)] DONE $preset rc=$?"
  bash panelB/stop.sh; sleep 8; prev_model="$model"
done
echo "[$(date -u +%H:%M:%S)] LADDER-FROM-35B COMPLETE (397B is on HPC, separate)"
