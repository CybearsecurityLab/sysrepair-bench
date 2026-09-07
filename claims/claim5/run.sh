#!/usr/bin/env bash
# Claim 5: recompute failure_modes from the shipped logs.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# Evaluation logs ship separately from the code; unpack them and point LOGS
# at them, or drop them in <repo>/logs.
LOGS="${LOGS:-$ROOT/logs}"
VENV="$ROOT/.venv"

[ -d "$VENV" ] || { echo "ERROR: run ./install.sh first (no $VENV)"; exit 2; }
[ -d "$LOGS" ] || { echo "ERROR: no logs at $LOGS; set LOGS=/path/to/logs"; exit 2; }
# shellcheck disable=SC1091
. "$VENV/bin/activate"

echo "[claim5] recomputing failure_modes from $LOGS"
python "$ROOT/scripts/analysis/make_failure_modes.py" --logs "$LOGS" --out "$HERE/observed.tsv"

echo
echo "[claim5] comparing against expected/failure_modes.tsv"
python "$ROOT/scripts/analysis/compare_tables.py" \
  --expected "$HERE/expected/failure_modes.tsv" \
  --observed "$HERE/observed.tsv" \
  --key-cols 2 --unpaired \
  --tolerance 0.05
