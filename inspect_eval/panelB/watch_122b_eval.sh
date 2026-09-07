#!/bin/bash
cd /home/resbears/projects/sysrepair-bench/inspect_eval
# One notification when the 122B eval proc exits (eval complete or died).
for i in $(seq 1 600); do   # up to 10h
  if ! pgrep -f 'sysrepair_bench.run panel_b_qwen_122b_a10b' >/dev/null 2>&1; then
    echo "122B EVAL FINISHED — proc exited. Compute pass@5 + CDR on the common-27 subset and fold in as the 5th ladder rung. Check panelB/run_panel_b_qwen_122b_a10b.log for rc."
    exit 0
  fi
  sleep 60
done
echo "122B eval watch timed out (10h) — investigate."
