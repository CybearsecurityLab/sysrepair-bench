#!/usr/bin/env bash
# SysRepair artifact installer.
#
# Two tiers, because most claims do not need a solver at all:
#
#   ./install.sh            logs-only tier. Python env + analysis deps. No
#                           Docker, no GPU, no credentials. Sufficient for ALL
#                           FIVE claims as they run by default.
#   ./install.sh --full     adds Docker image builds and vLLM. Needed only to
#                           re-run scenarios live (claim 4 with LIVE=1, or any
#                           from-scratch re-execution).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FULL=0; [ "${1:-}" = "--full" ] && FULL=1
say(){ printf '\n[install] %s\n' "$*"; }
fail(){ printf '\n[install] ERROR: %s\n' "$*" >&2; exit 1; }

say "checking python"
command -v python3 >/dev/null || fail "python3 not found"
PYV=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')
# 3.10 is the real floor: it is what inspect_ai declares (>=3.10), and every
# analysis script and the harness compile under it. Requiring 3.11 turned away
# Ubuntu 22.04, whose system python is 3.10.
python3 - <<'PY' || fail "python 3.10+ required (found $PYV)"
import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,10) else 1)
PY
say "python $PYV ok"

# Prefer uv when it is present: it is what built the environment these results
# were produced in, and it carries its own interpreter, so it works on hosts
# where Debian/Ubuntu split venv into a separate package.
USE_UV=0
say "creating virtualenv at $HERE/.venv"
if command -v uv >/dev/null 2>&1; then
  say "using uv"
  USE_UV=1
  uv venv --python 3.14 "$HERE/.venv" >/dev/null 2>&1 \
    || uv venv "$HERE/.venv" >/dev/null \
    || fail "uv could not create a virtualenv at $HERE/.venv"
else
  # Without uv, the stdlib path needs venv support, which Debian and Ubuntu
  # package separately; check first so this fails with advice rather than a
  # raw ensurepip traceback.
  python3 -c 'import ensurepip, venv' 2>/dev/null || fail \
    "python venv support is missing. Either install uv (https://astral.sh/uv) or, on Debian/Ubuntu: apt install python${PYV}-venv"
  python3 -m venv "$HERE/.venv" || fail "could not create virtualenv at $HERE/.venv"
fi
# shellcheck disable=SC1091
. "$HERE/.venv/bin/activate"
# A uv venv ships without pip on purpose; use `uv pip` against it instead.
if [ "$USE_UV" = "1" ]; then
  PIP="uv pip"; export VIRTUAL_ENV="$HERE/.venv"
else
  PIP="python -m pip"; python -m pip install --quiet --upgrade pip wheel
fi

say "installing analysis dependencies (logs-only tier)"
$PIP install --quiet -r "$HERE/requirements-analysis.txt"

# Put the harness on the path once, here, instead of making every claim script
# export PYTHONPATH. sysrepair_bench must be importable because the eval logs
# carry references to its custom sandbox provider: without it read_eval_log
# raises NotImplementedError and samples are silently skipped, which would look
# like empty results rather than a failure.
say "registering the harness on the venv path"
SITE=$(python -c 'import site;print(site.getsitepackages()[0])')
printf '%s\n' "$HERE/inspect_eval" > "$SITE/sysrepair_harness.pth"
python -c 'import sysrepair_bench' || fail "harness still not importable after registering it"

say "verifying the shipped logs are readable"
python "$HERE/scripts/analysis/verify_logs.py" || fail "shipped logs failed their integrity check"

if [ "$FULL" -eq 1 ]; then
  say "full tier: checking docker"
  command -v docker >/dev/null || fail "docker not found; needed for --full"
  docker info >/dev/null 2>&1 || fail "docker daemon not reachable; needed for --full"
  # The harness declares its own dependencies; there is no separate
  # requirements-full.txt. Installing the package pulls the solver stack in.
  say "installing the harness and its solver dependencies"
  $PIP install --quiet -e "$HERE/inspect_eval"

  # Base images are built by the harness, not by a shell script. prebuild
  # resolves the image set from run.BASE_IMAGES and builds what is missing.
  say "building scenario base images (slow on first run)"
  ( cd "$HERE/inspect_eval" && python -m sysrepair_bench.prebuild ) \
    || fail "base image build failed; check that the docker daemon is reachable"
  say "full tier ready. Claim 4 needs an API key: see claims/claim4/claim.txt"
else
  say "logs-only tier ready. All five claims are runnable now."
  say "To re-run scenarios live (claim 4 with LIVE=1), use: ./install.sh --full"
fi

cat <<'MSG'

[install] done.

  cd claims/claim1 && ./run.sh      reproduces the headline accuracy table
                                    from the shipped logs, no credentials

Each claims/claimN/ contains claim.txt describing exactly what is being
reproduced, its runtime, and whether it needs Docker, a GPU, or an API key.
MSG
