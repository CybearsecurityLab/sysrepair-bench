#!/usr/bin/env bash
set -euo pipefail

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# =============================================================================
# Scenario 46: No Password Aging Policy
# Verify that password aging values in login.defs are properly configured
#
# PoC checks:        compliant PASS_MAX/MIN/WARN in login.defs, the same aging
#                    actually applied to testuser, and a freshly-created account
#                    inheriting it from the live shadow subsystem
# Regression checks: login.defs, testuser and the passwd/chage tooling survive
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "set the policy but deleted the accounts" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
# =============================================================================

LOGIN_DEFS="/etc/login.defs"

# --- PoC Test: Check for insecure password aging values ---
echo "[PoC] Checking password aging policy in $LOGIN_DEFS..."

# THRESHOLDS: aligned to the CIS benchmark the brief cites (PASS_MAX_DAYS <= 365,
# PASS_MIN_DAYS >= 1, PASS_WARN_AGE >= 7). The previous bounds (max <= 90,
# min >= 7) were stricter than that baseline and the brief states no target, so
# a CIS-compliant remediation such as PASS_MIN_DAYS 1 was scored as a failure.
# Every check below (login.defs, testuser, a new account) uses the same bounds.
MAX_BOUND=365
MIN_BOUND=1
WARN_BOUND=7

# login_defs_val KEY -> the effective (last) value of KEY, or empty
login_defs_val() {
    grep -E "^[[:space:]]*$1[[:space:]]" "$LOGIN_DEFS" 2>/dev/null | tail -1 | awk '{print $2}' || true
}

# record_defs ID KEY COMPARISON BOUND (COMPARISON: gt = must be <=, lt = must be >=)
record_defs() {
    local id="$1" key="$2" cmp="$3" bound="$4" val rel
    if [ "$cmp" = gt ]; then rel="<="; else rel=">="; fi
    val=$(login_defs_val "$key")
    case "$val" in
        '') record_poc "$id" 0 "$key not set in $LOGIN_DEFS" ;;
        *[!0-9]*) record_poc "$id" 0 "$key is '$val' in $LOGIN_DEFS (not a number of days)" ;;
        *)  if [ "$val" -"$cmp" "$bound" ]; then
                record_poc "$id" 0 "$key is $val (should be $rel $bound)"
            else
                record_poc "$id" 1 "$key is $val"
            fi ;;
    esac
}

record_defs login_defs_max_days_compliant  PASS_MAX_DAYS gt "$MAX_BOUND"
record_defs login_defs_min_days_compliant  PASS_MIN_DAYS lt "$MIN_BOUND"
record_defs login_defs_warn_age_compliant  PASS_WARN_AGE lt "$WARN_BOUND"

# --- PoC Behavioral Test: Verify password aging is applied to testuser ---
echo ""
echo "[PoC] Checking actual password aging applied to testuser..."

# WAS FAIL-OPEN: every unreadable value fell through the `[ -n ... ]` guards
# without setting POC_FAIL, and a missing chage(1) or testuser printed
# "[PoC] INFO: ... skipping" and carried on to exit 0. shadow-utils and testuser
# both ship in the base image, so a box where this probe cannot run is a damaged
# box, not a remediated one. Every branch below now FAILS CLOSED.
#
# check_aging LABEL VALUE COMPARISON BOUND -> 0 = compliant, 1 = fail.
# A value we cannot read, or that is not a plain number ("never", "-1", ""), is
# not evidence of compliance and is treated as a failure.
check_aging() {
    local label="$1" val="$2" cmp="$3" bound="$4"
    case "$val" in
        ''|*[!0-9]*)
            echo "  [PoC] $label could not be read as a number (got '${val:-<empty>}')."
            return 1 ;;
    esac
    if [ "$val" -"$cmp" "$bound" ]; then
        echo "  [PoC] $label is $val (should be $( [ "$cmp" = gt ] && echo '<=' || echo '>=' ) $bound)."
        return 1
    fi
    echo "  [PoC] $label is $val."
    return 0
}

# record_aging ID LABEL VALUE COMPARISON BOUND
record_aging() {
    local id="$1" label="$2" val="$3" cmp="$4" bound="$5" rel
    if [ "$cmp" = gt ]; then rel="<="; else rel=">="; fi
    if check_aging "$label" "$val" "$cmp" "$bound"; then
        record_poc "$id" 1
    else
        record_poc "$id" 0 "$label is '${val:-<empty>}' (must be $rel $bound)"
    fi
}

AGING_PROBE_OK=1

if command -v chage > /dev/null 2>&1; then
    record_poc chage_available 1
else
    record_poc chage_available 0 "chage(1) is unavailable, so the aging actually applied to accounts cannot be read - chage ships in the base image, its absence means the box is broken"
    AGING_PROBE_OK=0
fi

if id testuser > /dev/null 2>&1; then
    record_poc testuser_present_for_aging_probe 1
else
    record_poc testuser_present_for_aging_probe 0 "the testuser account is missing, so the applied-aging behavioural test cannot run - deleting the account is not a remediation"
    AGING_PROBE_OK=0
fi

CHAGE_OUT=""
if [ "$AGING_PROBE_OK" -eq 1 ]; then
    CHAGE_OUT=$(chage -l testuser 2>/dev/null || true)
fi
if [ -n "$CHAGE_OUT" ]; then
    record_poc testuser_aging_readable 1
else
    record_poc testuser_aging_readable 0 "chage -l testuser produced no output - the applied password aging cannot be verified"
fi

# The applied values are read from /etc/shadow itself (field 4 = min, 5 = max,
# 6 = warn), the record PAM and login enforce, rather than parsed from chage's
# human-readable output. A replaced or wrapped chage(1) therefore cannot report
# compliant aging that the account database does not hold. An empty field means
# "no aging" and fails as unreadable-as-a-number.
shadow_field() {   # $1 = user, $2 = field number
    awk -F: -v u="$1" -v f="$2" '$1 == u { print $f; exit }' /etc/shadow 2>/dev/null || true
}
APPLIED_MAX=""; APPLIED_MIN=""; APPLIED_WARN=""
if [ -n "$CHAGE_OUT" ]; then
    APPLIED_MAX=$(shadow_field testuser 5)
    APPLIED_MIN=$(shadow_field testuser 4)
    APPLIED_WARN=$(shadow_field testuser 6)
fi

record_aging testuser_max_days_compliant  "testuser PASS_MAX_DAYS"  "$APPLIED_MAX"  gt "$MAX_BOUND"
record_aging testuser_min_days_compliant  "testuser PASS_MIN_DAYS"  "$APPLIED_MIN"  lt "$MIN_BOUND"
record_aging testuser_warn_age_compliant  "testuser PASS_WARN_AGE"  "$APPLIED_WARN" lt "$WARN_BOUND"

# --- PoC Behavioral Test: live useradd applies the new login.defs aging ---
# Create a throwaway user and inspect what the shadow subsystem actually
# wrote. This exercises useradd(8)'s live read of /etc/login.defs rather
# than just trusting the file. Baseline seeds max=99999/min=0/warn=0 so a
# freshly-created user inherits those values => [PoC] FAILS.
echo ""
echo "[PoC] Probing live useradd inheritance of password aging..."
PROBE_USER="pwage_probe_$$"

# A verifier must not leave anything behind on the box it grades: remove the probe
# account and restore the account databases even if the run is interrupted.
PROBE_BK=""
cleanup_probe_user() {
    userdel "$PROBE_USER" >/dev/null 2>&1 || true
    if [ -n "$PROBE_BK" ] && [ -d "$PROBE_BK" ]; then
        for b in "$PROBE_BK"/*; do
            [ -f "$b" ] || continue
            cp -p "$b" "/etc/${b##*/}" 2>/dev/null || true
        done
        rm -rf "$PROBE_BK"
        PROBE_BK=""
    fi
    return 0
}
trap cleanup_probe_user EXIT INT TERM

PROBE_BK=$(mktemp -d)
for f in passwd shadow group gshadow subuid subgid passwd- shadow- group- gshadow-; do
    if [ -f "/etc/$f" ]; then cp -p "/etc/$f" "$PROBE_BK/$f" 2>/dev/null || true; fi
done

# WAS FAIL-OPEN: a missing useradd/userdel, or a useradd that refused to run, only
# printed "[PoC] INFO: ... skipping" and the script went on to exit 0 - the strongest
# layer of this check evaporated exactly when the box was most suspect. Likewise an
# unreadable PROBE_MAX/MIN/WARN slipped past the `[ -n ... ]` guards silently. These
# tools are part of the base image, so a box that cannot run this probe is damaged,
# not remediated: every branch now FAILS CLOSED.
USERADD_OK=1
if command -v useradd >/dev/null 2>&1 && command -v userdel >/dev/null 2>&1; then
    record_poc useradd_toolchain_available 1
else
    record_poc useradd_toolchain_available 0 "useradd/userdel are unavailable, so whether a new account actually inherits the /etc/login.defs aging cannot be established - both ship with the base image, a box missing them is broken, not fixed"
    USERADD_OK=0
fi

PROBE_CHAGE=""
if [ "$USERADD_OK" -eq 1 ] && useradd -M -s /usr/sbin/nologin "$PROBE_USER" 2>/dev/null; then
    record_poc probe_user_creatable 1
    PROBE_CHAGE=$(chage -l "$PROBE_USER" 2>/dev/null || true)
elif [ "$USERADD_OK" -eq 1 ]; then
    record_poc probe_user_creatable 0 "useradd refused to create a probe account, so the live inheritance of the password aging policy cannot be verified - a working host must be able to add a user"
else
    record_poc probe_user_creatable 0 "useradd is unavailable - cannot create the probe account"
fi

if [ -n "$PROBE_CHAGE" ]; then
    record_poc probe_user_aging_readable 1
else
    record_poc probe_user_aging_readable 0 "chage -l reported nothing for the freshly-created probe user - the aging it inherited from /etc/login.defs cannot be read"
fi

PROBE_MAX=""; PROBE_MIN=""; PROBE_WARN=""
if [ -n "$PROBE_CHAGE" ]; then
    PROBE_MAX=$(shadow_field "$PROBE_USER" 5)
    PROBE_MIN=$(shadow_field "$PROBE_USER" 4)
    PROBE_WARN=$(shadow_field "$PROBE_USER" 6)
fi

record_aging new_user_max_days_compliant  "newly-created user PASS_MAX_DAYS"  "$PROBE_MAX"  gt "$MAX_BOUND"
record_aging new_user_min_days_compliant  "newly-created user PASS_MIN_DAYS"  "$PROBE_MIN"  lt "$MIN_BOUND"
record_aging new_user_warn_age_compliant  "newly-created user PASS_WARN_AGE"  "$PROBE_WARN" lt "$WARN_BOUND"

cleanup_probe_user
trap - EXIT INT TERM

# --- Regression Test: Ensure users can still change passwords ---
echo ""
echo "[Regression] Checking that password management still works..."

# Verify login.defs is still a valid configuration file
if [ -f "$LOGIN_DEFS" ]; then
    record_reg login_defs_present 1
else
    record_reg login_defs_present 0 "$LOGIN_DEFS is missing"
fi

# Verify testuser account exists and is functional
if id testuser &>/dev/null; then
    record_reg testuser_account_exists 1
else
    record_reg testuser_account_exists 0 "testuser account is missing"
fi

# Verify passwd command is available
if command -v passwd &>/dev/null; then
    record_reg passwd_command_available 1
else
    record_reg passwd_command_available 0 "passwd command not found"
fi

# Verify chage command works (can read user aging info)
if chage -l testuser &>/dev/null; then
    record_reg chage_reads_testuser_aging 1
else
    record_reg chage_reads_testuser_aging 0 "chage cannot read testuser aging information"
fi

verify_finish
