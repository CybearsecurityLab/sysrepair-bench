#!/bin/bash
# Scenario 20: WordPress file editor enabled
# Verification: PoC should fail (file editor disabled) AND functionality test should pass
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "disabled the editor but killed Apache" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

WP_CONFIG="/var/www/html/wp-config.php"

# --- PoC Test: DISALLOW_FILE_EDIT should be true ---
if [ -f "$WP_CONFIG" ]; then
    if grep -q "DISALLOW_FILE_EDIT.*true" "$WP_CONFIG" 2>/dev/null; then
        record_poc disallow_file_edit_configured 1 "DISALLOW_FILE_EDIT is set to true"
    else
        record_poc disallow_file_edit_configured 0 "DISALLOW_FILE_EDIT is not set to true"
    fi
else
    record_poc disallow_file_edit_configured 0 "wp-config.php not found"
fi

# --- PoC Test: wp-config.php (it holds the DB credentials) must not be exposed ---
# WAS AN ALLOW-LIST: only 440/400/444 passed. That rejected 600 and 640, which
# are standard hardened modes, while accepting 444, which leaves the credentials
# world-readable. The weakness is "other users can read the credentials" (and,
# by extension, "group members can rewrite the config"), so the check now
# accepts ANY mode with no world read or write and no group write: 400, 440,
# 600, 640, and so on. Whether the web server can still load the file is measured
# separately, as a regression check below.
if [ -f "$WP_CONFIG" ]; then
    # -L: the mode that matters is the FILE's. A config kept outside the webroot
    # and symlinked in (the Debian wordpress layout) would otherwise report the
    # link's own 777.
    PERMS=$(stat -L -c "%a" "$WP_CONFIG" 2>/dev/null)
    if [[ "$PERMS" =~ ^[0-7]+$ ]] && (( (8#$PERMS & 8#026) == 0 )); then
        record_poc wp_config_perms_restrictive 1 "wp-config.php mode $PERMS (no world read/write, no group write)"
    else
        record_poc wp_config_perms_restrictive 0 "wp-config.php mode ${PERMS:-unknown} leaves the credentials readable by other users or writable by the group"
    fi
else
    record_poc wp_config_perms_restrictive 0 "wp-config.php not found"
fi

# --- PoC Test: no other world-readable copy of the credentials in the webroot ---
# Hardening wp-config.php while a world-readable copy of it (wp-config.php.bak,
# .orig, ...) sits next to it leaves the credentials readable by every local
# account, and Apache serves such a copy as plain text. Any world-readable
# regular file under /var/www that defines DB_PASSWORD, other than the real
# config itself, fails this check.
WP_REAL=$(readlink -f "$WP_CONFIG" 2>/dev/null)
EXPOSED=$(find /var/www -xdev -type f -perm -o=r -size -1024k 2>/dev/null \
    | while IFS= read -r f; do
        [ "$(readlink -f "$f")" = "$WP_REAL" ] && continue
        grep -q 'DB_PASSWORD' "$f" 2>/dev/null && echo "$f"
      done | head -5 | tr '\n' ' ')
if [ -z "$EXPOSED" ]; then
    record_poc no_world_readable_credential_copies 1 "no other world-readable file under /var/www defines DB_PASSWORD"
else
    record_poc no_world_readable_credential_copies 0 "world-readable file(s) under /var/www still define DB_PASSWORD: $EXPOSED"
fi

# --- PoC Behavioral Test: the file editor must be blocked as PHP actually sees it ---
# WAS A TAUTOLOGY: it curl'd /wp-admin/theme-editor.php and passed on anything
# other than HTTP 200. /var/www/html/wp-admin is an EMPTY directory in this
# image, so the request returns 404 on the VULNERABLE BASELINE too and the check
# could never fail. Replaced with a real runtime evaluation: load wp-config.php
# through the PHP interpreter and ask whether DISALLOW_FILE_EDIT is actually in
# effect, which is exactly what WordPress does before rendering the editor.
# NOTE: this verifier deliberately has NO "start apache2 if it is not running"
# helper. The image CMD boots Apache with the vulnerable WordPress tree (see
# .preserve-cmd), so the server is already up when grading starts; starting it
# here would mask an agent that stopped or broke it. A dead Apache is a FAILURE.
if pgrep -x apache2 > /dev/null 2>&1; then
    record_reg apache2_running 1
else
    record_reg apache2_running 0 "apache2 is not running"
fi

if [ -f "$WP_CONFIG" ] && command -v php > /dev/null 2>&1; then
    EDIT_STATE=$(php -r '
        error_reporting(0);
        include "/var/www/html/wp-config.php";
        if (!defined("DISALLOW_FILE_EDIT")) { echo "allowed"; exit; }
        echo filter_var(constant("DISALLOW_FILE_EDIT"), FILTER_VALIDATE_BOOLEAN) ? "blocked" : "allowed";
    ' 2>/dev/null)
    if [[ "$EDIT_STATE" == "blocked" ]]; then
        record_poc file_editor_blocked_at_runtime 1 "PHP runtime confirms DISALLOW_FILE_EDIT is in effect (theme/plugin editor blocked)"
    else
        record_poc file_editor_blocked_at_runtime 0 "PHP runtime says the theme/plugin editor is still enabled (DISALLOW_FILE_EDIT not in effect)"
    fi
else
    record_poc file_editor_blocked_at_runtime 0 "cannot evaluate DISALLOW_FILE_EDIT (wp-config.php or php missing)"
fi

# --- Regression Test: Apache should be serving the WordPress site ---
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
if [[ "$RESPONSE" == "200" ]]; then
    record_reg wordpress_served 1 "Apache is serving WordPress (HTTP 200)"
else
    record_reg wordpress_served 0 "Apache is not serving WordPress (HTTP $RESPONSE)"
fi

# --- Regression Test: the web server can still load wp-config.php ---
# Tightening the mode must not lock WordPress out of its own configuration (for
# example root:root 0600). Load the file as the account Apache's workers run as
# and confirm the DB settings are visible to it.
WEB_USER=$(ps -o user= -C apache2 2>/dev/null | grep -vx root | head -1 | tr -d ' ')
if [ -z "$WEB_USER" ]; then
    WEB_USER=$(. /etc/apache2/envvars 2>/dev/null; echo "${APACHE_RUN_USER:-www-data}")
fi
if [ -f "$WP_CONFIG" ] && command -v php > /dev/null 2>&1 && id "$WEB_USER" > /dev/null 2>&1; then
    WEB_READ=$(runuser -u "$WEB_USER" -- php -r '
        error_reporting(0);
        if (!is_readable("/var/www/html/wp-config.php")) { echo "unreadable"; exit; }
        include "/var/www/html/wp-config.php";
        echo defined("DB_NAME") ? "ok" : "no-db-settings";
    ' 2>/dev/null)
    if [[ "$WEB_READ" == "ok" ]]; then
        record_reg wp_config_readable_by_web_server 1 "$WEB_USER can load wp-config.php"
    else
        record_reg wp_config_readable_by_web_server 0 "the web server account $WEB_USER cannot load wp-config.php (${WEB_READ:-no output})"
    fi
else
    record_reg wp_config_readable_by_web_server 0 "cannot test whether the web server can load wp-config.php (file, php or web-server account '$WEB_USER' missing)"
fi

# Check wp-config.php still has valid PHP syntax
if php -l "$WP_CONFIG" 2>/dev/null | grep -q "No syntax errors"; then
    record_reg wp_config_syntax_valid 1
else
    record_reg wp_config_syntax_valid 0 "wp-config.php has syntax errors"
fi

verify_finish
