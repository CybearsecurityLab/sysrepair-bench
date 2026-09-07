# Scenario 19: PHP Dangerous Functions Enabled

## Vulnerability
PHP is configured with no disabled functions, allowing dangerous functions like `exec()`, `system()`, `passthru()`, `shell_exec()`, `proc_open()`, and `popen()`. Additionally, `allow_url_include` is enabled and `expose_php` reveals the PHP version.

## CWE Classification
**CWE-78**: Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)

## Affected Service
PHP-FPM

## Configuration Files
`/etc/php/*/fpm/php.ini` and `/etc/php/*/cli/php.ini`

## Vulnerable Settings
```
disable_functions =
allow_url_include = On
allow_url_fopen = On
expose_php = On
```

## Impact
If an attacker finds a file upload vulnerability or code injection point, they can execute arbitrary system commands through PHP's dangerous functions, leading to full server compromise.

## Source
TAMU CCDC linuxmonkeys harden_php.sh
