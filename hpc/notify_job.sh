#!/usr/bin/env bash
# Watch a Delta job and report every STATE CHANGE, including why it is pending.
#
# Why this exists alongside --mail-type in vllm_serve.slurm, rather than instead:
#   1. Slurm has NO notification for the pending state. A job is pending from the
#      moment sbatch returns, which is not a transition, so mail never fires and
#      you cannot tell "queued behind 1800 jobs" from "will never run". This
#      script reports the scheduler's own Reason field, which distinguishes them.
#   2. Site mail relays are frequently disabled on HPC systems and fail SILENTLY:
#      the directive is accepted, sbatch succeeds, and no mail is ever sent. Until
#      one BEGIN mail actually arrives, treat Delta email as unproven.
#
# RUNS LOCALLY, polling over ssh. It deliberately does NOT run on the login node:
# the standing rule is that no work happens there, and a long-lived poll loop is
# exactly the kind of thing that rule exists to stop. squeue is invoked per tick
# and exits.
#
# Usage: hpc/notify_job.sh <jobid> [poll_seconds]
set -u
JOB="${1:?usage: notify_job.sh <jobid> [poll_seconds]}"
POLL="${2:-60}"
SSH=(ssh -o ControlPath="$HOME/.ssh/cm-delta" -o BatchMode=yes -o ConnectTimeout=15 delta)

say(){ printf '%s  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
prev=""
miss=0
say "watching job $JOB every ${POLL}s"
while :; do
  # %T state, %r reason, %N nodelist, %S predicted start, %L time left
  line=$("${SSH[@]}" "squeue -j $JOB -h -o '%T|%r|%N|%S|%L'" 2>/dev/null)
  rc=$?
  if [ $rc -ne 0 ]; then
    miss=$((miss+1))
    say "ssh unreachable (rc=$rc, ${miss} consecutive)"
    # Do NOT infer the job died from an ssh failure. Losing the control socket
    # and losing the job look identical from here, and calling a live job dead is
    # the more expensive mistake.
    sleep "$POLL"; continue
  fi
  miss=0
  if [ -z "$line" ]; then
    # Gone from the queue: finished, cancelled or purged. sacct knows which.
    fin=$("${SSH[@]}" "sacct -j $JOB -n -X -o State,ExitCode,Elapsed 2>/dev/null | head -1" 2>/dev/null)
    say "LEFT QUEUE: ${fin:-no sacct record}"
    exit 0
  fi
  if [ "$line" != "$prev" ]; then
    IFS='|' read -r st rs nd start left <<<"$line"
    case "$st" in
      PENDING) say "PENDING  reason=$rs  predicted_start=$start" ;;
      RUNNING) say "RUNNING  node=$nd  time_left=$left" ;;
      *)       say "$st  reason=$rs  node=$nd" ;;
    esac
    prev="$line"
  fi
  sleep "$POLL"
done
