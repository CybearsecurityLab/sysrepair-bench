#!/bin/bash
cd /home/resbears/projects/sysrepair-bench/inspect_eval
sleep 120
for i in $(seq 1 300); do
  if ! ps -eo args | grep -qE '[p]ython.*panel_b_qwen_397b'; then
    echo "397B EVAL FINISHED. Compute day1+zero_day pass@5 + CDR on the common-27 subset and fold the 6th rung into fig:ladder/tab:ladder + Fable-review."
    exit 0
  fi
  sleep 60
done
echo "397B watch timeout"
