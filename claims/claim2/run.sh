#!/usr/bin/env bash
# Claim 2: recompute hivestorm from the shipped logs.
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

echo "[claim2] recomputing hivestorm from $LOGS"
python "$ROOT/scripts/analysis/make_hivestorm.py" --logs "$LOGS" --out "$HERE/observed.tsv"

echo
echo "[claim2] comparing against expected/hivestorm.tsv"
python "$ROOT/scripts/analysis/compare_tables.py" \
  --expected "$HERE/expected/hivestorm.tsv" \
  --observed "$HERE/observed.tsv" \
  --tolerance 0.05
