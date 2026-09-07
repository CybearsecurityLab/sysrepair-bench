#!/bin/bash
cd /home/resbears/projects/sysrepair-bench/inspect_eval
sleep 120  # let it start
for i in $(seq 1 600); do
  if ! pgrep -f 'sysrepair_bench.run panel_b_qwen_122b_a10b' >/dev/null 2>&1 && [ -f panelB/run_panel_b_qwen_122b_zd.log ]; then
    rc=$(grep -oE 'eval exited rc=[0-9]+' panelB/launch_122b_zd_wrap.log 2>/dev/null | tail -1)
    echo "122B BLACK-BOX RE-RUN FINISHED ($rc). Compute zero_day pass@5+CDR on common-27, then fold BOTH 122B conditions into fig:ladder/tab:ladder (5th rung) + Fable-review."
    exit 0
  fi
  sleep 60
done
echo "122B zero_day re-run watch timed out."
