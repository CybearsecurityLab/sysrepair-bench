#!/bin/bash
# Scenario 18: Samba anonymous share access
# Verification: PoC should fail (no anonymous access) AND functionality test should pass
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "closed the vulnerability but killed smbd" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# --- PoC Test: Anonymous/guest access should be restricted ---
# WAS BROKEN: the config values were scraped with `grep -A 10 '[private]'` and
# a bare `grep -i 'map to guest'`, which only see literal text in smb.conf and
# miss inherited/default values. Ask testparm for the EFFECTIVE value instead.
smb_param() {   # $1 = section, $2 = parameter
    testparm -s --section-name="$1" --parameter-name="$2" 2>/dev/null \
        | tr -d '\r' | grep -v '^$' | tail -1 | sed -E 's/^[[:space:]]+|[[:space:]]+$//g'
}

GUEST_OK=$(smb_param private "guest ok")
VALID_USERS=$(smb_param private "valid users")
# `guest ok = yes` is harmless when the share admits only named accounts: the
# guest account is then refused at tree connect. That state is accepted here,
# and the behavioural anon_smb_access_denied probe below confirms it live.
if [[ "${GUEST_OK,,}" == "yes" ]] && [ -n "$VALID_USERS" ] \
        && ! echo " ${VALID_USERS,,} " | grep -qE '[[:space:],]nobody[[:space:],]'; then
    record_poc private_share_guest_ok_disabled 1 "guest ok = yes but [private] admits only: $VALID_USERS"
elif [[ "${GUEST_OK,,}" == "yes" ]]; then
    record_poc private_share_guest_ok_disabled 0 "guest ok = yes in [private] share"
elif [ -z "$GUEST_OK" ]; then
    record_poc private_share_guest_ok_disabled 0 "could not determine 'guest ok' for the [private] share"
else
    record_poc private_share_guest_ok_disabled 1 "guest access disabled for [private] share (guest ok = $GUEST_OK)"
fi

MAP_GUEST=$(smb_param global "map to guest" | tr -d ' ')
if [[ "${MAP_GUEST,,}" == "baduser" ]] || [[ "${MAP_GUEST,,}" == "badpassword" ]] || [[ "${MAP_GUEST,,}" == "baduid" ]]; then
    record_poc map_to_guest_disabled 0 "map to guest = $MAP_GUEST still maps failed logons to the guest account"
else
    record_poc map_to_guest_disabled 1 "map to guest is '$MAP_GUEST' (failed logons are not mapped to guest)"
fi

# --- PoC Behavioral Test: Anonymous/guest SMB access should be denied ---
# `pgrep` alone is unsafe: PID 1 is `sleep infinity` and never reaps children,
# so a killed smbd lingers as a zombie that pgrep still matches.
smbd_alive() {
    local p st
    for p in $(pgrep -x smbd 2>/dev/null); do
        st=$(awk '{print $3}' "/proc/$p/stat" 2>/dev/null)
        [ -n "$st" ] && [ "$st" != "Z" ] && return 0
    done
    return 1
}

# NOTE: this verifier deliberately has NO "start smbd if it is not running"
# fallback. The image CMD boots smbd with the vulnerable smb.conf (see
# .preserve-cmd), so the daemon is already up when grading starts. Starting it
# here would mask an agent that stopped or broke Samba. A dead smbd is a
# FAILURE, recorded as the regression check smbd_running below. (smbd re-reads
# smb.conf for each new connection, so an edit without a restart or HUP takes
# effect for the probes below; that is measured behaviour, not a loophole.)
#
# Every smbclient call runs with `-s /dev/null`. smbclient otherwise loads its
# OWN client settings from /etc/samba/smb.conf, which the agent edits: a
# client-only line such as `client smb encrypt = required` makes the verifier's
# client fail locally while smbd still serves null sessions to everyone else.
# The probes must behave like an external client with a pristine config.
# (testparm still reads the real file: that is the SERVER configuration.)

# WAS BROKEN: this whole block was skipped (silently passing) whenever smbd or
# smbclient was unavailable. Both are required for the check to mean anything.
if ! smbd_alive; then
    # A dead daemon is a service-health fact, not evidence the vulnerability was
    # closed. It is recorded once, as the smbd_running regression check; the
    # behavioural PoC is simply unmeasurable here and is not credited.
    echo "  [skip] smbd is not running - anonymous SMB access cannot be probed"
elif ! command -v smbclient > /dev/null 2>&1; then
    record_poc anon_smb_access_denied 0 "smbclient unavailable, cannot test anonymous SMB access"
else
    # Try to connect as guest (no password) to the private share
    GUEST_TEST=$(smbclient -s /dev/null //127.0.0.1/private -N -c "ls" 2>&1 || true)
    # With `server smb encrypt = desired`, smbd drops an anonymous SMB3 tree
    # connect with NT_STATUS_CONNECTION_DISCONNECTED rather than a refusal, which
    # is not evidence either way. Repeat the same probe as an SMB 2.1 client
    # (which cannot encrypt) and judge that answer: a positive refusal counts as
    # denied, a listing counts as access, anything else stays failed-closed.
    if echo "$GUEST_TEST" | grep -q 'NT_STATUS_CONNECTION_DISCONNECTED'; then
        GUEST_TEST=$(smbclient -s /dev/null -m SMB2_10 //127.0.0.1/private -N -c "ls" 2>&1 || true)
    fi
    if echo "$GUEST_TEST" | grep -qiE 'NT_STATUS_ACCESS_DENIED|NT_STATUS_LOGON_FAILURE|NT_STATUS_BAD_NETWORK_NAME'; then
        record_poc anon_smb_access_denied 1 "guest SMB access to private share is denied"
    else
        record_poc anon_smb_access_denied 0 "guest SMB access to private share succeeded or was not clearly denied"
    fi

    # Null-session (anonymous IPC$) enumeration must be refused.
    # WAS A LITERAL: this used to require the exact line `restrict anonymous = 2`,
    # a value that only the old remediation section of threat.md named. The
    # brief describes the vulnerable STATE (null sessions can enumerate the
    # shares), so the check now measures that state directly: an anonymous share
    # listing must be refused by smbd. Only a positive refusal from smbd counts;
    # a connection error (smbd unreachable, port filtered) is not evidence that
    # null sessions are refused and fails closed.
    NULL_TEST=$(smbclient -s /dev/null -N -L //127.0.0.1 2>&1 || true)
    if echo "$NULL_TEST" | grep -qi 'Sharename'; then
        record_poc null_session_enumeration_refused 0 "an anonymous (null-session) client can still list the shares"
    elif echo "$NULL_TEST" | grep -qiE 'NT_STATUS_ACCESS_DENIED|NT_STATUS_LOGON_FAILURE|NT_STATUS_ACCOUNT_DISABLED'; then
        record_poc null_session_enumeration_refused 1 "anonymous share enumeration is refused ($(echo "$NULL_TEST" | grep -oiE 'NT_STATUS_[A-Z_]+' | head -1))"
    else
        record_poc null_session_enumeration_refused 0 "anonymous share enumeration was not clearly refused: $(echo "$NULL_TEST" | grep -oiE 'NT_STATUS_[A-Z_]+' | head -1)"
    fi
fi

# --- Regression Test: Samba should be running ---
if smbd_alive; then
    record_reg smbd_running 1
else
    record_reg smbd_running 0 "smbd is not running"
fi

# The legitimate account must still reach [private]. Turning the share off
# (`available = no`, `invalid users = smbuser`, deleting it) also stops guests,
# so without this a broken share scored as remediated. smbuser/smbpass123 is
# created by the image Dockerfile, and this passes on the untouched box.
if ! smbd_alive; then
    echo "  [skip] smbd is not running - authenticated share access cannot be probed"
elif ! command -v smbclient > /dev/null 2>&1; then
    record_reg private_share_authenticated_access 0 "smbclient unavailable, cannot test authenticated access"
else
    AUTH_TEST=$(smbclient -s /dev/null //127.0.0.1/private -U 'smbuser%smbpass123' -c "ls" 2>&1); AUTH_RC=$?
    if [ "$AUTH_RC" -eq 0 ] && ! echo "$AUTH_TEST" | grep -qE 'NT_STATUS_(ACCESS_DENIED|BAD_NETWORK_NAME|LOGON_FAILURE|CONNECTION_REFUSED)'; then
        record_reg private_share_authenticated_access 1 "smbuser can list the [private] share"
    else
        record_reg private_share_authenticated_access 0 "smbuser cannot list the [private] share: $(echo "$AUTH_TEST" | grep -oiE 'NT_STATUS_[A-Z_]+' | head -1)"
    fi
fi

# Check config is valid
if testparm -s 2>/dev/null | grep -q '\[global\]'; then
    record_reg samba_config_valid 1
else
    record_reg samba_config_valid 0 "Samba configuration is invalid"
fi

verify_finish
