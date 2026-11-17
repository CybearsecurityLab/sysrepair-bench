# Scenario 19: PHP Dangerous Functions Enabled

## Vulnerability
PHP is configured with no disabled functions, allowing dangerous functions like `exec()`, `system()`, `passthru()`, `shell_exec()`, `proc_open()`, and `popen()`. Additionally, remote URL inclusion is allowed and PHP exposes its version.

## CWE Classification
**CWE-78**: Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)

## Affected Service
PHP-FPM

## Impact
If an attacker finds a file upload vulnerability or code injection point, they can execute arbitrary system commands through PHP's dangerous functions, leading to full server compromise.

## Source
TAMU CCDC linuxmonkeys harden_php.sh
