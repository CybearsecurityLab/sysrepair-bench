#!/usr/bin/env bash
# Regenerate every claim's expected/ table from the FINAL logs, then verify the
# artifact by running every claim exactly as an ACSAC evaluator will.
#
# WHY THIS EXISTS: the expected/ tables were generated while evaluation was
# still running, so they describe smaller populations than the logs now hold
# (claim1 showed 52 match / 10 differ, every difference an n change; claim5
# reproduced nothing at all). Regenerating by hand invites transcription
# errors and a half-updated set, which is exactly the failure mode that makes
# an artifact look fabricated. This does the whole set from one source.
#
# RUN THIS ONLY WHEN THE EVALUATION LEGS ARE COMPLETE. Running it mid-flight
# bakes a partial population into expected/, and the artifact then certifies
# whatever happened to be finished that hour.
#
#   ./finalize.sh              regenerate + verify
#   ./finalize.sh --verify     verify only, change nothing
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$HERE/.venv"
# Evaluation logs are distributed separately from the code (they are large and
# are not kept in git). Unpack them anywhere and point LOGS at them.
LOGS="${LOGS:-$HERE/logs}"
NSLOGS="${NSLOGS:-$HERE/logs/nsplan/logs_final30}"
VERIFY_ONLY=0; [ "${1:-}" = "--verify" ] && VERIFY_ONLY=1

say(){ printf '\n[finalize] %s\n' "$*"; }
[ -d "$VENV" ] || { echo "ERROR: run ./install.sh first"; exit 2; }
# shellcheck disable=SC1091
. "$VENV/bin/activate"
export PYTHONPATH="$HERE/inspect_eval${PYTHONPATH:+:$PYTHONPATH}"
A="$HERE/scripts/analysis"

if [ "$VERIFY_ONLY" = "0" ]; then
  say "regenerating expected/ tables from $LOGS"

  say "claim1: headline accuracy"
  python "$A/make_headline.py" --logs "$LOGS" --k 1,5 \
    --out "$HERE/claims/claim1/expected/headline.tsv" \
    || echo "  WARNING: claim1 regeneration failed"

  say "claim2: hivestorm"
  if python "$A/make_hivestorm.py" --logs "$LOGS" \
       --out "$HERE/claims/claim2/expected/hivestorm.tsv" 2>/dev/null; then
    :
  else
    echo "  SKIPPED: no hivestorm logs yet. tab:hivestorm reports MiniMax-M2.7"
    echo "           and Qwen3.5-9B; until those runs land claim2 cannot ship."
  fi

  say "claim3: cost"
  python "$A/make_cost.py" --logs "$LOGS" \
    --out "$HERE/claims/claim3/expected/cost.tsv" \
    || echo "  WARNING: claim3 regeneration failed"

  say "claim4: NeuroPlan dispositions"
  python "$A/nsplan_dispositions.py" --logs "$NSLOGS" --suite vulnhub \
    --out "$HERE/claims/claim4/expected/dispositions.tsv" >/dev/null \
    || echo "  WARNING: claim4 regeneration failed"

  say "claim5: failure modes"
  python "$A/make_failure_modes.py" --logs "$LOGS" \
    --out "$HERE/claims/claim5/expected/failure_modes.tsv" \
    || echo "  WARNING: claim5 regeneration failed"
fi

say "verifying: running every claim as an evaluator would"
pass=0; fail=0
for c in "$HERE"/claims/claim*/; do
  n=$(basename "$c")
  # No skip branch on purpose: a claim whose expected/ is empty should RUN and
  # fail with its own error ("no hivestorm episodes under ..."), which names
  # the missing data. Skipping would hide it behind a softer word.
  if (cd "$c" && ./run.sh >/tmp/finalize_$n.log 2>&1); then
    echo "  $n  PASS"; pass=$((pass+1))
  else
    echo "  $n  FAIL  (see /tmp/finalize_$n.log)"
    tail -3 "/tmp/finalize_$n.log" | sed 's/^/        /'
    fail=$((fail+1))
  fi
done

say "$pass passed, $fail failed"
if [ "$fail" -gt 0 ]; then
  echo "The artifact is NOT ready to ship: every claim must pass."
  exit 1
fi
echo "All claims reproduce. Zip WITHOUT .venv (it is ~321M and install.sh"
echo "regenerates it):"
echo "    zip -r sysrepair-artifact.zip . -x '.venv/*' -x '*/__pycache__/*'"
