# Cacti — Unauthenticated Command Injection via remote_agent.php (CVE-2022-46169)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-46169
- CWE-78: Improper Neutralization of Special Elements used in an OS Command

## Description
Cacti versions before 1.2.23 contain an unauthenticated command injection
vulnerability in `remote_agent.php`. The script processes a `local_data_id`
(or similar) parameter that is passed without sanitisation to a PHP
`shell_exec()` call inside the poller execution chain. An attacker can append
shell metacharacters to inject arbitrary operating system commands, which
execute with the privileges of the web server process.

Example exploit:
```
GET /remote_agent.php?action=polldata&local_data_id=1;id HTTP/1.1
Host: cacti.target
```
Returns:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

No authentication is required. The endpoint is reachable by any client that
can send an HTTP request to the server.

## Affected Service
- **Service:** Cacti ≤ 1.2.22 (simulated with Apache+PHP)
- **Port:** 80/TCP (or 8080 in this scenario)
- **Vulnerable endpoint:** `/remote_agent.php`

## Constraints
- Cacti must not be upgraded; it stays at version 1.2.22 or earlier.
