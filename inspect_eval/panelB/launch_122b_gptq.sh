#!/bin/bash
cd /home/resbears/projects/sysrepair-bench/inspect_eval
set -a; . ./.env >/dev/null 2>&1; set +a
SNAP=~/.cache/huggingface/hub/models--Qwen--Qwen3.5-122B-A10B-GPTQ-Int4/snapshots
echo "[gptq] waiting for download to finish..."
for i in $(seq 1 480); do   # up to 8h of waiting
  if ! pgrep -f 'hf download Qwen/Qwen3.5-122B-A10B-GPTQ' >/dev/null 2>&1; then
    # download proc gone — verify files present
    if ls $SNAP/*/config.json >/dev/null 2>&1 && ls $SNAP/*/*.safetensors >/dev/null 2>&1; then
      echo "[gptq] download complete; files present"; break
    fi
  fi
  sleep 60
done
HF=$(cat /home/resbears/.cache/huggingface/token 2>/dev/null || echo "")
docker rm -f pbvllm >/dev/null 2>&1
echo "[gptq] serving GPTQ-Int4 (GPU-resident, no offload, served-name = base model so eval matches)"
docker run -d --name pbvllm --gpus all --shm-size 24g \
  -v /home/resbears/.cache/huggingface:/root/.cache/huggingface \
  -e HF_TOKEN="$HF" -e HUGGING_FACE_HUB_TOKEN="$HF" \
  -e PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True -p 8100:8000 \
  vllm/vllm-openai:latest \
  --model Qwen/Qwen3.5-122B-A10B-GPTQ-Int4 \
  --served-model-name Qwen/Qwen3.5-122B-A10B \
  --tensor-parallel-size 2 --gpu-memory-utilization 0.97 --max-model-len 49152 \
  --enforce-eager --max-num-batched-tokens 8192 \
  --trust-remote-code --enable-auto-tool-choice --tool-call-parser qwen3_coder --enable-prefix-caching >/dev/null
echo "[gptq] container up; waiting for /health..."
for i in $(seq 1 120); do
  curl -s --max-time 4 http://localhost:8100/health >/dev/null 2>&1 && { echo "[gptq] HEALTHY after ~$((i*15))s"; break; }
  if ! docker ps --format '{{.Names}}'|grep -q pbvllm; then echo "[gptq] CONTAINER DIED — check docker logs pbvllm"; exit 1; fi
  sleep 15
done
echo "[gptq] launching 122B eval (cascade-scoped, 27 scen)"
uv run python -m sysrepair_bench.run panel_b_qwen_122b_a10b \
  --runs panelB/cascade_122b_zeroday.runs.yaml \
  > panelB/run_panel_b_qwen_122b_zd.log 2>&1
echo "[gptq] eval exited rc=$?"
