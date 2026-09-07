#!/bin/bash
cd /home/resbears/projects/sysrepair-bench/inspect_eval
# Exit (=notify) when 122B eval starts producing samples, OR vLLM/eval fails.
for i in $(seq 1 240); do   # up to 4h
  # failure: container gone
  if ! docker ps --format '{{.Names}}' | grep -q pbvllm; then
    echo "122B FAILURE: pbvllm container is gone (crashed/OOM). Check panelB/serve_122b_bnb.log + docker logs."
    exit 1
  fi
  # failure: OOM/error in vLLM log
  if docker logs pbvllm 2>&1 | grep -qiE "CUDA out of memory|torch.*OutOfMemory|EngineDeadError|raise RuntimeError|Engine core init failed"; then
    echo "122B FAILURE: vLLM logged an OOM/engine error. Pivot to fp8+cpu-offload."
    exit 1
  fi
  # success signal: eval log has a completed sample (inspect writes progress)
  if [ -f panelB/run_panel_b_qwen_122b_a10b.log ]; then
    n=$(grep -cE "sample|completed|zero_day|day1" panelB/run_panel_b_qwen_122b_a10b.log 2>/dev/null)
    if [ "${n:-0}" -gt 0 ]; then
      echo "122B EVAL RUNNING: serve healthy, eval producing (log has $n progress lines). Fold rung in when complete."
      exit 0
    fi
  fi
  sleep 60
done
echo "122B WATCH TIMEOUT (4h) with no eval progress — investigate."
