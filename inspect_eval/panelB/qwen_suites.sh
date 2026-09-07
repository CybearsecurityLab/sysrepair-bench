#!/usr/bin/env bash
cd "$(dirname "$0")/.."
echo "[qwen_suites] waiting for vLLM :8100 health..."
for i in $(seq 1 240); do curl -s --max-time 4 http://localhost:8100/health >/dev/null 2>&1 && break; sleep 10; done
echo "[qwen_suites] vLLM ready; running Qwen-4B on remaining suites (full, epochs=3, no cascade)"
uv run python -m sysrepair_bench.run rest_qwen_4b --runs runs.yaml
uv run python -m sysrepair_bench.run hivestorm_qwen_4b --runs runs.yaml
echo "[qwen_suites] DONE $(date -u +%FT%TZ)"
