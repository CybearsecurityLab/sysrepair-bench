#!/bin/bash
# 397B orchestrator: wait for a Delta vllm-q35 job to RUN+serve, tunnel to it via
# the Delta ControlMaster (no Duo), then run the 397B eval on the common-27 subset.
cd /home/resbears/projects/sysrepair-bench/inspect_eval
set -a; . ./.env >/dev/null 2>&1; set +a
JOBS="20933317 20965992"
say(){ echo "[$(date -u +%H:%M:%S)] $*"; }
say "orchestrator up; watching jobs: $JOBS"

JOB=""; CONN=""
for i in $(seq 1 900); do            # ~15h max, poll 60s (keeps master warm)
  for j in $JOBS; do
    st=$(ssh -o BatchMode=yes -o ConnectTimeout=15 delta "squeue -j $j -h -o %T" 2>/dev/null)
    if [ "$st" = "RUNNING" ]; then
      c=$(ssh -o BatchMode=yes -o ConnectTimeout=15 delta "cat ~/.vllm_delta/conn_${j}.env 2>/dev/null" 2>/dev/null)
      [ -n "$c" ] && { JOB=$j; CONN="$c"; break; }
    fi
  done
  [ -n "$JOB" ] && break
  sleep 60
done
[ -z "$JOB" ] && { say "no serving job after wait window; giving up"; exit 1; }

NODE=$(echo "$CONN" | grep -oP 'VLLM_NODE=\K\S+')
PORT=$(echo "$CONN" | grep -oP 'VLLM_PORT=\K\S+')
KEY=$(echo  "$CONN" | grep -oP 'VLLM_API_KEY=\K\S+')
say "job $JOB serving on $NODE:$PORT"

# wait for vLLM /health on the compute node (397B load is slow), probed from login
for i in $(seq 1 80); do
  h=$(ssh -o BatchMode=yes -o ConnectTimeout=15 delta "curl -s -o /dev/null -w '%{http_code}' --max-time 8 http://${NODE}:${PORT}/health" 2>/dev/null)
  [ "$h" = "200" ] && { say "vLLM healthy on compute node"; break; }
  say "waiting for 397B to load (health=$h)"; sleep 30
done

# tunnel local :8001 -> NODE:PORT via the Delta master (reuses ControlMaster, no Duo)
ssh -o BatchMode=yes -N -f -L 127.0.0.1:8001:${NODE}:${PORT} delta 2>/dev/null
sleep 4
lh=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 http://localhost:8001/health 2>/dev/null)
say "local :8001 health=$lh"
[ "$lh" != "200" ] && { say "tunnel unhealthy; abort"; exit 1; }

# scope to the common-27 subset (35B failures) and run the eval
export DELTA_VLLM_KEY="$KEY"
uv run python panelB/cascade_prep.py Qwen3.5-35B-A3B panel_b_qwen_397b \
  --out panelB/cascade_397b.runs.yaml 2>&1 | tail -2
say "launching 397B eval (day1 first, then zero_day)"
uv run python -m sysrepair_bench.run panel_b_qwen_397b \
  --runs panelB/cascade_397b.runs.yaml > panelB/run_panel_b_qwen_397b.log 2>&1
say "397B eval exited rc=$?"
