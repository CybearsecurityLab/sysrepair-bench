#!/bin/bash
###############################################################################
# Scenario 11 - Verification Script
# MySQL remote root login + no bind-address
#
# PoC checks:        bind-address is restricted and skip-grant-tables is gone,
#                    in the config AND at runtime
# Regression checks: mysqld is running and testdb is still readable
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed the vulnerability but killed mysqld" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
###############################################################################

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# WAS BROKEN: the runtime bind-address check used `ss -tlnp`, but iproute2 is
# NOT installed in this image. `ss` failed silently, LISTEN_ADDR came back empty
# and the check was skipped entirely - the config grep was the only thing
# enforcing anything. These helpers parse /proc/net/tcp{,6} instead
# (state 0A = LISTEN, $2 = HEXIP:HEXPORT; 3306 = 0x0CEA).
# `pgrep` alone is also unsafe here: PID 1 is `sleep infinity` and never reaps,
# so killed daemons linger as zombies that pgrep still matches.
proc_alive() {
    local p st
    for p in $(pgrep -x "$1" 2>/dev/null); do
        st=$(awk '{print $3}' "/proc/$p/stat" 2>/dev/null)
        [ -n "$st" ] && [ "$st" != "Z" ] && return 0
    done
    return 1
}

listener_on_3306() {   # 0 = something is LISTENing on 3306
    awk 'NR>1 && $4=="0A" {split($2,a,":"); if (a[2]=="0CEA") f=1} END{exit !f}' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

wildcard_listener_on_3306() {  # 0 = LISTENing on 0.0.0.0 / :: (all interfaces)
    awk 'NR>1 && $4=="0A" {split($2,a,":"); if (a[2]=="0CEA" && a[1] ~ /^0+$/) f=1} END{exit !f}' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

# WAS BROKEN (design): this used to be an `ensure_mysqld` helper that STARTED
# the daemon when it was not running. The image CMD now boots mysqld with the
# vulnerable config (see .preserve-cmd), so a daemon is always expected here.
# Starting one would load the agent's edited my.cnf and silently repair the
# "edited the config but never restarted mysqld" mistake - and would equally
# hide a daemon the agent stopped or broke. A dead mysqld is a FAILURE.
mysqld_alive() {
    proc_alive mysqld
}

# --- PoC check: bind-address should be 127.0.0.1 ---
BIND=$(grep -rE '^\s*bind-address' /etc/mysql/ 2>/dev/null | grep -v '#' | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
if [[ "$BIND" == "0.0.0.0" ]] || [[ "$BIND" == "*" ]] || [[ -z "$BIND" ]]; then
    record_poc bind_address_restricted 0 "bind-address is '$BIND' (should be 127.0.0.1)"
else
    record_poc bind_address_restricted 1 "bind-address is '$BIND'"
fi

# --- PoC check: skip-grant-tables should not be set ---
SKIP_GRANTS=$(grep -rE '^\s*skip-grant-tables' /etc/mysql/ 2>/dev/null | grep -v '#')
if [ -n "$SKIP_GRANTS" ]; then
    record_poc skip_grant_tables_unset 0 "skip-grant-tables is still enabled"
else
    record_poc skip_grant_tables_unset 1
fi

# --- Regression check: mysqld must still be alive ---
#
# The behavioural PoC checks below can only be MEASURED against a live daemon.
# A dead mysqld is recorded here as the regression failure it is, and those
# probes are then skipped rather than being scored as if they had run.
mysqld_alive
MYSQLD_UP=$?
if [ "$MYSQLD_UP" -eq 0 ]; then
    record_reg mysqld_running 1
else
    record_reg mysqld_running 0 "mysqld is not running"
fi

# --- PoC behavioural check: skip-grant-tables should be gone at runtime ---
if [ "$MYSQLD_UP" -eq 0 ]; then
    # WAS BROKEN: `X=$(mysql ... 2>/dev/null && echo ok || echo denied)` captures
    # the QUERY OUTPUT as well, so a successful login yielded "1\n1\nok", which
    # is != "ok" and was misreported as "access denied". stdout must be silenced.
    SKIP_GRANT_TEST=$(mysql -u root --skip-password -e "SELECT 1" >/dev/null 2>&1 && echo "ok" || echo "denied")
    if [[ "$SKIP_GRANT_TEST" == "ok" ]]; then
        # This could mean skip-grant-tables is active OR root has no password.
        # Check more specifically: try an obviously-wrong password
        WRONG_PW_TEST=$(mysql -u root -p'__wrong_pw_verify__' -e "SELECT 1" >/dev/null 2>&1 && echo "ok" || echo "denied")
        if [[ "$WRONG_PW_TEST" == "ok" ]]; then
            record_poc runtime_auth_enforced 0 "MySQL accepts any credentials - skip-grant-tables likely still active"
        else
            record_poc runtime_auth_enforced 1 "MySQL root can connect without password but rejects wrong passwords (auth is enforced)"
        fi
    else
        record_poc runtime_auth_enforced 1 "unauthenticated MySQL access denied (skip-grant-tables is off)"
    fi
else
    echo "  [SKIP] mysqld is not running - runtime authentication cannot be measured"
fi

# --- PoC behavioural check: verify bind address at runtime ---
if [ "$MYSQLD_UP" -ne 0 ]; then
    echo "  [SKIP] mysqld is not running - the runtime bind address cannot be measured"
elif wildcard_listener_on_3306; then
    record_poc runtime_no_wildcard_listener 0 "MySQL is listening on 0.0.0.0/:: port 3306 at runtime"
elif listener_on_3306; then
    record_poc runtime_no_wildcard_listener 1 "MySQL is bound to a restricted address at runtime (no wildcard listener on 3306)"
else
    record_poc runtime_no_wildcard_listener 1 "MySQL has no TCP listener on 3306 at all (networking disabled)"
fi

# --- Regression check: testdb must still be accessible ---
#
# WAS BROKEN: this was a bare `mysql -u root`, which hard-requires passwordless
# root. Setting a root password is ordinary, defensible hardening — the
# runtime_auth_enforced PoC above explicitly PASSES that state — yet it made
# this command fail and scored the agent as having destroyed the database. The
# check is about DATA AVAILABILITY, not about which credential state the box
# ends in (cf. scenario-25, whose redis probe reads the configured password and
# uses it when set). Credential sources are tried in order; each is shipped by
# the image or created by the agent, never guessed:
#   1. root over the unix socket — covers auth_socket, empty-password and
#      skip-grant states, and picks up /root/.my.cnf if the agent stored the
#      new password there;
#   2. the package maintenance account via /etc/mysql/debian.cnf, which this
#      image ships as auth_socket with authentication_string=root, so the OS
#      root user may always use it;
#   3. if BOTH attempts die with a client authentication denial (ERROR
#      1045/1698) — a response only a live, auth-enforcing mysqld can give —
#      testdb is verified on disk instead: the items tablespace must still be
#      present, non-empty, in the datadir.
# A dead daemon (ERROR 2002/2003), a dropped database (ERROR 1049) or a dropped
# table still FAIL: none of those reaches a passing tier.
_try_testdb() {   # $@ = mysql client args; sets TESTDB_COUNT / TESTDB_ERR
    local out
    out=$(mysql "$@" -N --batch -e "SELECT COUNT(*) FROM testdb.items;" 2>&1)
    if [ $? -eq 0 ]; then
        TESTDB_COUNT=$(printf '%s\n' "$out" | tail -1); TESTDB_ERR=""
        return 0
    fi
    TESTDB_COUNT=""; TESTDB_ERR="$out"
    return 1
}
_auth_denied() {  # $1 = mysql client error text
    printf '%s' "$1" | grep -qE 'ERROR (1045|1698)|Access denied for user'
}

TESTDB_COUNT=""; TESTDB_ERR=""; ROOT_ERR=""; CRED_NOTE="read as root over the unix socket"
if ! _try_testdb -u root; then
    ROOT_ERR="$TESTDB_ERR"
    if [ -r /etc/mysql/debian.cnf ] && _try_testdb --defaults-file=/etc/mysql/debian.cnf; then
        CRED_NOTE="root login requires a password; read via the debian.cnf maintenance account"
    fi
fi
if [ -n "$TESTDB_COUNT" ]; then
    if [ "$TESTDB_COUNT" -ge 1 ] 2>/dev/null; then
        record_reg testdb_accessible 1 "$CRED_NOTE"
    else
        record_reg testdb_accessible 0 "testdb.items is reachable but empty (count='$TESTDB_COUNT')"
    fi
elif _auth_denied "$ROOT_ERR" && _auth_denied "$TESTDB_ERR"; then
    DATADIR=$(grep -rhE '^[[:space:]]*datadir[[:space:]]*=' /etc/mysql/ 2>/dev/null | tail -1 \
        | sed -e 's/^[^=]*=[[:space:]]*//' -e 's/[[:space:]]*$//')
    [ -n "$DATADIR" ] && [ -d "$DATADIR" ] || DATADIR=/var/lib/mysql
    if [ -s "$DATADIR/testdb/items.ibd" ]; then
        record_reg testdb_accessible 1 "every local credential is password-protected (auth enforced by a live mysqld); testdb.items verified on disk in $DATADIR"
    else
        record_reg testdb_accessible 0 "auth is enforced and $DATADIR/testdb/items.ibd is missing - testdb appears dropped"
    fi
else
    record_reg testdb_accessible 0 "testdb is not accessible: ${TESTDB_ERR:-${ROOT_ERR:-unknown error}}"
fi

verify_finish
