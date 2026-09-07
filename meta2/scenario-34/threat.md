# PHP-CGI Query-String RCE

## Severity
**High** — CVSS 7.5

## CVE
CVE-2012-1823

## Category
Compensating Controls (service upgrade would break the dependent legacy application)

## Description
PHP 5.2.x in CGI mode interprets query strings beginning with a dash as command-line flags,
enabling source disclosure (`?-s`) and RCE via `?-d+allow_url_include=1+-d+auto_prepend_file=...`.

This scenario hosts a legacy Mutillidae-style application (`/cgi-bin/legacy.php`) that depends
on PHP-CGI invocation semantics — upgrading PHP or migrating to mod_php is out of scope
because it breaks the dependent application.

## Affected Service / Port
- Apache HTTP Server with PHP-CGI
- Port 80/TCP

## Constraints
- PHP must not be upgraded and the application must not be migrated to mod_php.
- The legacy application at `/cgi-bin/legacy.php` must remain functional.

## Out of Scope
- Upgrading PHP (breaks legacy app — dependency scenario S19 already covers that path).
- Removing the CGI symlink (breaks legacy app).
