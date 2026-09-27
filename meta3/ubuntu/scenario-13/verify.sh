#!/bin/bash
# Verification for meta3-ubuntu/scenario-13: Drupal 7.5 (Drupalgeddon,
# CVE-2014-3704) pinned -- ModSecurity WAF compensating control.
# Exit 0 = every check passed, Exit 1 = at least one check failed.
#
# DYNAMIC: the two Drupalgeddon payloads are fired at the LIVE Apache. The WAF
# module is only attached after Apache is restarted, so "wrote the rules but did
# not restart Apache" correctly FAILS (payload is not blocked -> not 403).
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "blocked the payloads by tearing Apache down" reports security_pass=true /
# regression_pass=false instead of collapsing into a bare exit 1.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# A 200 alone does not prove Drupal is serving: when Drupal cannot reach MySQL
# it renders its "Error | Drupal" maintenance page with HTTP 200. Blocking the
# database (e.g. `ALL: ALL` in hosts.deny, which this libwrap-linked mysqld
# honours) then read as a healthy site. Require the page itself to be served.
drupal_home_ok() {
    _body=$(timeout 20 curl -s -w '\n%{http_code}' http://localhost/drupal/ 2>/dev/null || true)
    _code=$(printf '%s' "$_body" | tail -n1)
    DRUPAL_HOME_CODE=$_code
    [ "$_code" = "200" ] || return 1
    if printf '%s' "$_body" | grep -Eqi '<title>Error \||PDOException|Error while reading greeting packet|unexpected error'; then
        DRUPAL_HOME_CODE="200 (Drupal error page: database unreachable)"
        return 1
    fi
    return 0
}

C="timeout 10 curl -sg"   # -g/--globoff: payload URLs contain [ ] which curl would treat as globs

# Runtime evidence #1: the module must actually be loaded into the running server.
if apache2ctl -M 2>/dev/null | grep -qi 'security2'; then
    record_poc modsecurity_loaded 1
else
    record_poc modsecurity_loaded 0 "mod_security2 is not loaded in the running Apache"
fi

###############################################################################
# PoC: Drupalgeddon payloads must be blocked (HTTP 403) by the live WAF.
###############################################################################
# Read-only payload body of the SAME shape the WAF matches ("name[0 ;...").
# The WAF keys on the shape, not the SQL effect, so a benign SELECT proves the
# block without risking a destructive write in the not-yet-protected path.
P1=$($C -o /dev/null -w '%{http_code}' \
  -X POST 'http://localhost/drupal/?q=node&destination=node' \
  --data 'name[0 ;SELECT 1;#]=foo&pass=foo&form_id=user_login_block' || true)
if [ "$P1" = "403" ]; then
    record_poc name_array_payload_blocked 1
else
    record_poc name_array_payload_blocked 0 "Drupalgeddon name-array payload returned HTTP $P1 (expected 403 from the WAF)"
fi

P2=$($C -o /dev/null -w '%{http_code}' \
  'http://localhost/drupal/?q=node&destination=node&name[%23post_render][]=passthru&name[%23type]=markup&name[%23markup]=id' || true)
if [ "$P2" = "403" ]; then
    record_poc post_render_payload_blocked 1
else
    record_poc post_render_payload_blocked 0 "Drupalgeddon post_render payload returned HTTP $P2 (expected 403 from the WAF)"
fi

###############################################################################
# Regression: homepage and a legitimate login POST must still work.
###############################################################################
if drupal_home_ok; then
    record_reg drupal_homepage_200 1
else
    record_reg drupal_homepage_200 0 "/drupal/ returned HTTP $DRUPAL_HOME_CODE (expected a served page -- service down or over-blocked)"
fi

LOGIN=$($C -o /dev/null -w '%{http_code}' \
  -X POST 'http://localhost/drupal/?q=user&destination=user' \
  --data 'name=admin&pass=wrongpassword&form_id=user_login&op=Log+in' || true)
if [ "$LOGIN" = "403" ]; then
    record_reg legit_login_not_blocked 0 "legitimate Drupal login POST was blocked (403) -- rules too broad"
else
    record_reg legit_login_not_blocked 1 "legitimate login POST passed the WAF (HTTP $LOGIN)"
fi

verify_finish
