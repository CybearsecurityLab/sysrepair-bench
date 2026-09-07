# PHP-CGI Query String Parameter Injection (Remote Code Execution)

## Severity
**High** -- CVSS 7.5

## CVE
CVE-2012-1823

## Description
PHP versions before 5.3.12 and before 5.4.2 (when configured as a CGI script, typically via `php-cgi`) do not properly handle query strings that lack an unencoded `=` character. This allows remote attackers to inject command-line options via the query string. For example:

- `?-s` -- Displays PHP source code (information disclosure)
- `?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input` -- Enables remote code execution by injecting PHP configuration directives

An attacker can achieve full remote code execution on the web server by crafting a malicious HTTP request to any PHP-CGI endpoint.

Ubuntu 8.04 ships PHP 5.2.x, which is vulnerable to this attack when PHP is deployed in CGI mode.

## Affected Service / Port
- **Service:** Apache HTTP Server with PHP-CGI
- **Port:** 80

## Vulnerable Version
- PHP < 5.3.12 (5.3.x branch)
- PHP < 5.4.2 (5.4.x branch)
- PHP 5.2.x (all versions, as shipped on Ubuntu 8.04)
