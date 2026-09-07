#!/bin/bash
# Verification script for Scenario 10: Credential Reuse (payroll DB == OS passwords)
# Exit 0 = every check passed, Exit 1 = at least one check failed
#
# CRITICAL FIX vs. the earlier version: it probed reuse with
#     echo "$DB_PASS" | su -c true "$ACCOUNT"
# but this verifier runs as ROOT, and root's `su` never asks for a password --
# so su ALWAYS returned 0, making the check pass at baseline for the wrong
# reason AND making a correct remediation impossible to detect (still exit 1).
#
# We instead compare directly: does the payroll DB password, hashed with the
# account's own /etc/shadow salt, equal the stored OS hash? That is exactly
# "the DB password is the OS password", with no root-exemption and no su.
# Read-only: the box is not mutated.
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "rotated the OS passwords but broke the payroll app" reports
# security_pass=true / regression_pass=false instead of a bare exit 1.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

ACCOUNTS="leia_organa han_solo artoo_detoo c_three_pio"

# WAS BROKEN: every query below ran as a bare `mysql -u root payroll`, which
# succeeds only because the image ships /root/.my.cnf holding the ORIGINAL root
# password. Rotating a shared, well-known database password is ordinary
# hardening, and on a credential-reuse scenario it is arguably part of the
# remediation itself, yet it made every query return nothing: the reuse PoC
# became unmeasurable AND the payroll database was reported as destroyed. The
# question here is whether the reuse still exists and whether the app still
# works, not which root credential the box ends on. Sources are tried in order;
# each is shipped by the image or written by the agent, never guessed.
MYSQL_ARGS=""
_mysql_ok() { mysql "$@" -N --batch -e "SELECT 1 FROM payroll.users LIMIT 1;" >/dev/null 2>&1; }
if   _mysql_ok -u root;            then MYSQL_ARGS="-u root"
elif _mysql_ok -u root -psploitme; then MYSQL_ARGS="-u root -psploitme"
elif [ -r /etc/mysql/debian.cnf ] && _mysql_ok --defaults-file=/etc/mysql/debian.cnf; then
     MYSQL_ARGS="--defaults-file=/etc/mysql/debian.cnf"
fi

db_pass_for() {   # $1 = account; prints the payroll DB password, empty if unreadable
    [ -n "$MYSQL_ARGS" ] || return 1
    mysql $MYSQL_ARGS payroll -sNe "SELECT password FROM users WHERE username='$1' LIMIT 1;" 2>/dev/null
}

# The payroll tablespace on disk. Used only when EVERY credential above was
# refused by a live mysqld: that proves auth is enforced, not that the data is
# gone, and the two must not be scored the same way.
payroll_table_on_disk() {
    local dd
    dd=$(grep -rhE '^[[:space:]]*datadir[[:space:]]*=' /etc/mysql/ 2>/dev/null | tail -1 \
        | sed -e 's/^[^=]*=[[:space:]]*//' -e 's/[[:space:]]*$//')
    [ -n "$dd" ] && [ -d "$dd" ] || dd=/var/lib/mysql
    [ -s "$dd/payroll/users.ibd" ]
}

# perl provides crypt() with $6$ (SHA-512) support via glibc. Without it the
# reuse question cannot be answered at all, so it is a PoC failure.
if ! command -v perl >/dev/null 2>&1; then
    record_poc shadow_hash_comparable 0 "perl is required for the shadow-hash comparison but is missing"
fi

os_pw_matches() {  # $1=account $2=candidate-password  -> exit 0 if it is the OS password
    local acct="$1" cand="$2" hash
    hash=$(getent shadow "$acct" 2>/dev/null | cut -d: -f2)
    case "$hash" in
        '$'*) : ;;                       # a real hash we can test
        *) return 2 ;;                   # locked/empty/absent -> cannot match a password
    esac
    ACCT_HASH="$hash" CAND="$cand" perl -e '
        my ($salt) = $ENV{ACCT_HASH} =~ /^(\$[0-9a-z]+\$[^\$]+\$)/;
        exit 2 unless defined $salt;
        exit( crypt($ENV{CAND}, $salt) eq $ENV{ACCT_HASH} ? 0 : 1 );
    '
}

# --- PoC: no OS account may share its password with the payroll DB ---
CHECKED=0
for A in $ACCOUNTS; do
    DB_PASS=$(db_pass_for "$A" || true)
    if [ -z "$DB_PASS" ]; then
        echo "INFO: account '$A' not in payroll DB -- skipping." >&2
        continue
    fi
    CHECKED=$((CHECKED+1))
    os_pw_matches "$A" "$DB_PASS"
    case $? in
        0) record_poc "no_reuse_$A" 0 "OS account '$A' still uses the payroll DB password" ;;
        1) record_poc "no_reuse_$A" 1 ;;
        *) record_poc "no_reuse_$A" 1 "OS account '$A' cannot authenticate with the DB password (no usable hash)" ;;
    esac
done
if [ "$CHECKED" -eq 0 ]; then
    # The original's own message names the cause ("DB down?") but scored it
    # purely as a PoC failure, so the service damage it describes was invisible.
    # Both are now recorded: the PoC failure keeps the original strictness (an
    # unanswerable reuse question is never credited as remediated) and the
    # regression failure names the damage that caused it. Nothing was weakened;
    # a state that used to exit 1 still exits 1.
    record_poc reuse_measurable 0 "could not read any probe account from the payroll DB, so the reuse question cannot be answered"
    if payroll_table_on_disk; then
        # Every shipped credential was refused but the data is still present:
        # the agent tightened database authentication, which is not damage.
        record_reg payroll_db_readable 1 "no shipped credential is accepted any more (database authentication was tightened); payroll.users verified on disk"
    else
        record_reg payroll_db_readable 0 "the payroll database is unreadable and payroll.users is not on disk - the database is gone"
    fi
fi

# --- Regression: the payroll app must still authenticate with the DB password ---
for A in $ACCOUNTS; do
    DB_PASS=$(db_pass_for "$A" || true)
    [ -z "$DB_PASS" ] && continue
    HTTP_CODE=$(timeout 20 curl -so /dev/null -w '%{http_code}' \
        -X POST http://localhost/payroll_app.php \
        --data "username=${A}&password=${DB_PASS}&submit=Login" || true)
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
        record_reg "payroll_login_$A" 1
    else
        record_reg "payroll_login_$A" 0 "payroll_app.php returned HTTP $HTTP_CODE for '$A' -- app broken"
    fi
done

verify_finish
