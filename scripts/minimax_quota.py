#!/usr/bin/env python3
"""Report REMAINING MiniMax Token Plan quota for every key we hold.

Generic infrastructure: not panel, ladder, or paper specific.

WHY NOT AN API PROBE. An earlier version of this sent a 1-token chat request
and reported whether it succeeded. That is a LIVENESS check, not a quota check:
it never returns a balance, it cannot say how much is left or when the window
rolls, and a bare 429 does not distinguish "usage exhausted" from "throttled
right now". It also spends quota to learn nothing quantitative. `mmx quota
show` returns the actual remaining percentages and the time to reset.

WHY --api-key RATHER THAN `mmx auth login`. --api-key is a global flag that
overrides all other auth, so each key is passed per invocation. No login, no
logging out and back in to check the second key, and no copy of either key
written into the CLI's own config.

Requires: npm install -g mmx-cli

    scripts/minimax_quota.py             both keys, all model classes
    scripts/minimax_quota.py --text      only the class the text evals use
    scripts/minimax_quota.py --json      raw JSON per key, for a watcher
    scripts/minimax_quota.py --quiet     one line per key
"""
from __future__ import annotations
import json, os, shutil, subprocess, sys, time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ENV_FILE = Path(os.environ.get("ENV_FILE", REPO / "inspect_eval" / ".env"))
KEY_VARS = ["MINIMAX_API_KEY", "MINIMAX_API_KEY_2"]


def read_key(var: str) -> str:
    """Read one value out of the env file. Never printed, never exported."""
    try:
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith(var + "="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return ""


def fetch(key: str) -> dict | None:
    # The CLI prints a region line before the JSON, so keep from the first brace.
    try:
        out = subprocess.run(["mmx", "quota", "show", "--api-key", key,
                              "--output", "json"],
                             capture_output=True, text=True, timeout=90).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    i = out.find("{")
    if i < 0:
        return None
    try:
        return json.loads(out[i:])
    except json.JSONDecodeError:
        return None


def hhmm(ms) -> str:
    s = max(0, int(ms or 0)) // 1000
    h, m = divmod(s // 60, 60)
    return f"{h}h{m:02d}m"


def report(label: str, key: str, mode: str) -> None:
    if not key:
        print(f"{label}: not set in {ENV_FILE.name}")
        return
    d = fetch(key)
    if d is None:
        print(f"{label}: no usable response (network, bad key, or CLI error)")
        return
    if mode == "--json":
        print(f"--- {label}")
        print(json.dumps(d, indent=1))
        return

    rows = d.get("model_remains") or []
    if not rows:
        print(f"{label}: response carried no model_remains")
        return
    if mode == "--text":
        rows = [r for r in rows if str(r.get("model_name")) in ("general", "text")]

    if mode == "--quiet":
        g = next((r for r in rows if str(r.get("model_name")) in ("general", "text")), rows[0])
        print(f"{label} interval={g.get('current_interval_remaining_percent')}% "
              f"weekly={g.get('current_weekly_remaining_percent')}% "
              f"resets_in={hhmm(g.get('remains_time'))}")
        return

    print(label)
    print(f"  {'model':<10} {'interval':>9} {'weekly':>8} {'resets in':>10}  used int/wk")
    for r in rows:
        name = str(r.get("model_name", "?"))
        ip = r.get("current_interval_remaining_percent")
        wp = r.get("current_weekly_remaining_percent")
        used = f"{r.get('current_interval_usage_count', 0)}/{r.get('current_weekly_usage_count', 0)}"
        # status 1 = active window; anything else is worth surfacing
        st = r.get("current_interval_status")
        flag = "" if st == 1 else f"   [interval status {st}]"
        print(f"  {name:<10} {str(ip) + '%':>9} {str(wp) + '%':>8} "
              f"{hhmm(r.get('remains_time')):>10}  {used}{flag}")


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if not shutil.which("mmx"):
        print("ERROR: mmx not on PATH. Install with: npm install -g mmx-cli",
              file=sys.stderr)
        print("       Installed under nvm? add $HOME/.nvm/versions/node/*/bin to PATH.",
              file=sys.stderr)
        return 2
    if not ENV_FILE.exists():
        print(f"ERROR: no env file at {ENV_FILE}", file=sys.stderr)
        return 2

    if mode != "--quiet":
        print(f"MiniMax Token Plan quota  ({time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())})\n")
    for i, var in enumerate(KEY_VARS):
        report(var, read_key(var), mode)
        if mode not in ("--quiet",) and i + 1 < len(KEY_VARS):
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
