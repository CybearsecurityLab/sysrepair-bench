#!/usr/bin/env bash
# Claim 4: NeuroPlan stage decomposition (Val / Plan / Exec) on vulnhub.
#
# Default mode recomputes the table from the SHIPPED logs and needs no
# credentials, no GPU and no Docker. That is deliberate: the pipeline's LLM
# stages make a live re-run stochastic, so the reproducible artifact is the
# recomputation, and the live re-run is an optional extra.
#
#   (default)     recompute from artifact/nsplan_logs/logs_final30
#   LIVE=1        additionally re-run the pipeline on three scenarios
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
VENV="$ROOT/.venv"
LOGS="${LOGS:-$ROOT/logs/nsplan/logs_final30}"

[ -d "$VENV" ] || { echo "ERROR: run ./install.sh first (no $VENV)"; exit 2; }
[ -d "$LOGS" ] || { echo "ERROR: no NeuroPlan logs at $LOGS"; exit 2; }
# shellcheck disable=SC1091
. "$VENV/bin/activate"

# The dispositions script imports sysrepair_bench.task to register the custom
# sandbox provider. Without the harness on PYTHONPATH every log raises
# NotImplementedError and each sample is skipped, which would report an empty
# table instead of failing loudly.
export PYTHONPATH="$ROOT/inspect_eval${PYTHONPATH:+:$PYTHONPATH}"

echo "[claim4] recomputing vulnhub stage decomposition from $LOGS"
python "$ROOT/scripts/analysis/nsplan_dispositions.py" \
  --logs "$LOGS" --suite vulnhub --out "$HERE/observed_dispositions.tsv"

echo
echo "[claim4] comparing against expected/dispositions.tsv"
# Exact diff, not compare_tables.py: dispositions are categorical, so there is
# no tolerance to apply, and any difference at all is a real difference.
if diff -u "$HERE/expected/dispositions.tsv" "$HERE/observed_dispositions.tsv"; then
  echo "[claim4] PASS: every scenario disposition and the summary row match."
else
  echo "[claim4] FAIL: recomputed dispositions differ from expected (diff above)."
  exit 1
fi

if [ "${LIVE:-0}" = "1" ]; then
  echo
  echo "[claim4] LIVE re-run requested"
  command -v docker >/dev/null || { echo "ERROR: docker required for LIVE=1"; exit 2; }
  docker info >/dev/null 2>&1 || { echo "ERROR: docker daemon not reachable"; exit 2; }
  if [ -z "${MINIMAX_API_KEY:-}${OPENAI_API_KEY:-}" ]; then
    echo "ERROR: LIVE=1 needs a hosted-model key for the state-lifting step."
    echo "       export MINIMAX_API_KEY=...  (or OPENAI_API_KEY + OPENAI_BASE_URL)"
    exit 2
  fi
  # Chosen to span three dispositions (plan-fail, execute-fail, success) so a
  # live run exercises a refusal path and a success path, not only the happy one.
  python "${NSPLAN_REPO:?set NSPLAN_REPO to a checkout of the NeuroPlan repo}/run_pipeline.py" --collection vulnhub \
    --scenarios scenario-03,scenario-09,scenario-14 \
    --output-dir "${OUT:-$HERE/nsplan_out}"
  echo "[claim4] a live run may move a scenario by one bucket; see HONEST SCOPE."
fi
