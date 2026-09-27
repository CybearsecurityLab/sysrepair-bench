#!/bin/bash
# Verification for meta3-ubuntu/scenario-18: Drupal web.config sensitive file
# disclosure over Apache. Exit 0 = every check passed, Exit 1 = at least one
# check failed.
#
# DYNAMIC: the file is requested from the LIVE Apache. Apache reads the deny
# directive only at (re)start, so "wrote the config but did not reload" leaves
# web.config served -> FAIL.
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "denied web.config by stopping Apache" reports security_pass=true /
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

C="timeout 10 curl -s"

###############################################################################
# PoC: /drupal/web.config must be denied (403) and must not leak its XML body.
#
# Only a real 403 counts, exactly as before: curl's 000 "no response" is not
# evidence that a deny rule was deployed, so it still fails. Service death is
# caught by the regression checks below, which is where it belongs.
###############################################################################
CODE=$($C -o /dev/null -w '%{http_code}' http://localhost/drupal/web.config || true)
if [ "$CODE" = "403" ]; then
    record_poc web_config_denied 1
else
    record_poc web_config_denied 0 "/drupal/web.config returned HTTP $CODE (expected 403)"
fi

BODY=$($C http://localhost/drupal/web.config || true)
if echo "$BODY" | grep -qi '<configuration'; then
    record_poc web_config_body_not_leaked 0 "response body still contains the web.config XML -- file is being served"
else
    record_poc web_config_body_not_leaked 1
fi

###############################################################################
# Regression: Drupal must still serve normally.
###############################################################################
if drupal_home_ok; then
    record_reg drupal_homepage_200 1
else
    record_reg drupal_homepage_200 0 "/drupal/ returned HTTP $DRUPAL_HOME_CODE (expected a served page)"
fi

PHP=$($C -o /dev/null -w '%{http_code}' http://localhost/drupal/index.php || true)
if [ "$PHP" = "200" ]; then
    record_reg drupal_index_php_200 1
else
    record_reg drupal_index_php_200 0 "/drupal/index.php returned HTTP $PHP (expected 200 -- rule too broad)"
fi

verify_finish
