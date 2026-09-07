#!/usr/bin/env bash
# Claim 1: recompute the headline accuracy table from the shipped logs.
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

echo "[claim1] recomputing headline table from $LOGS"
python "$ROOT/scripts/analysis/make_headline.py" \
  --logs "$LOGS" --k 1,5 --out "$HERE/observed.tsv"

echo
echo "[claim1] comparing against expected/headline.tsv"
python "$ROOT/scripts/analysis/compare_tables.py" \
  --expected "$HERE/expected/headline.tsv" \
  --observed "$HERE/observed.tsv" \
  --tolerance 0.05
