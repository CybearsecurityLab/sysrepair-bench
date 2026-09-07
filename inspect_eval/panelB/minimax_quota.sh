#!/usr/bin/env bash
# Report the live quota state of every MiniMax key, without the mmx CLI.
#
# WHY NOT THE CLI: `mmx auth login --api-key ...` authenticates ONE key at a
# time, so checking two keys means logging out and back in between them, and it
# writes the key into the CLI's own config. We hold two keys
# (MINIMAX_API_KEY and MINIMAX_API_KEY_2) and want both in one glance, so this
# probes the API directly instead. No npm, no global install, no second copy of
# the key on disk.
#
# HOW IT DECIDES: MiniMax reports quota failures in the JSON body's `base_resp`
# rather than only in the HTTP status, so both are read. The codes seen in
# practice:
#   1000/0  request served                     -> quota available
#   2056    Token Plan USAGE limit reached     -> the window is exhausted
#   2062    Token Plan RATE limit reached      -> window open but throttling
#   1004    authentication failure             -> wrong or revoked key
# 2056 and 2062 are different situations and the difference matters: 2056 means
# wait for the window to roll, 2062 means the window is open and the key is
# being throttled right now, so a serialised run may still make progress.
#
#   panelB/minimax_quota.sh            probe every key
#   panelB/minimax_quota.sh --quiet    one line per key, for a watcher loop
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$HERE/../.env}"
BASE="${MINIMAX_BASE_URL:-https://api.minimax.io/v1}"
MODEL="${MINIMAX_PROBE_MODEL:-MiniMax-M2.7}"
QUIET=0; [ "${1:-}" = "--quiet" ] && QUIET=1

[ -f "$ENV_FILE" ] || { echo "ERROR: no env file at $ENV_FILE" >&2; exit 2; }

# Read values without exporting the whole file or echoing anything.
getkey() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"'"'"' \r'; }
mask()   { local k="$1"; [ ${#k} -gt 12 ] && printf '%s...%s' "${k:0:6}" "${k: -4}" || printf '(short)'; }

probe() {   # $1 = label, $2 = key
    local label="$1" key="$2" body http resp code msg
    [ -n "$key" ] || { printf '%-22s %-14s %s\n' "$label" "ABSENT" "not set in $(basename "$ENV_FILE")"; return; }
    body=$(printf '{"model":"%s","messages":[{"role":"user","content":"ping"}],"max_tokens":1}' "$MODEL")
    resp=$(curl -s -m 30 -w '\n%{http_code}' -X POST "$BASE/chat/completions" \
             -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
             -d "$body" 2>/dev/null)
    http=$(printf '%s' "$resp" | tail -1)
    payload=$(printf '%s' "$resp" | sed '$d')
    code=$(printf '%s' "$payload" | grep -oE '"status_code"[[:space:]]*:[[:space:]]*[0-9]+' | head -1 | grep -oE '[0-9]+$')
    msg=$(printf '%s' "$payload"  | grep -oE '"status_msg"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4)

    case "${code:-}" in
        1000|0|"") [ "$http" = "200" ] && state="OK"          || state="HTTP $http" ;;
        2056)      state="USAGE-LIMIT" ;;
        2062)      state="RATE-LIMIT" ;;
        1004)      state="AUTH-FAIL" ;;
        *)         state="code $code" ;;
    esac
    printf '%-22s %-14s %s\n' "$label" "$state" "${msg:-http $http}"
}

K1=$(getkey MINIMAX_API_KEY)
K2=$(getkey MINIMAX_API_KEY_2)

if [ "$QUIET" = "0" ]; then
    echo "MiniMax quota  ($BASE, probe model $MODEL)"
    echo "key 1 = $(mask "$K1")   key 2 = $(mask "$K2")"
    printf '%-22s %-14s %s\n' "KEY" "STATE" "DETAIL"
fi
probe "MINIMAX_API_KEY"   "$K1"
probe "MINIMAX_API_KEY_2" "$K2"
