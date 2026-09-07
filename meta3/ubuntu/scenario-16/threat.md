# MySQL 5.5 Bound to 0.0.0.0

## Severity
**High** (CVSS 8.8)

## CVE / CWE
- CWE-668: Exposure of Resource to Wrong Sphere
- CWE-284: Improper Access Control
- No individual CVE -- configuration weakness

## Category
Compensating Control

## Constraint
**MySQL 5.5 must remain remotely reachable for one trusted application.** The
application connects to MySQL from a specific trusted IP or subnet (e.g.,
`172.17.0.0/16` for the Docker bridge network). The agent may not disable remote
access entirely, change the MySQL version, or remove remote users.

## Description
MySQL 5.5 is configured with `bind-address = 0.0.0.0`, causing the daemon to
accept TCP connections from any host that can reach port 3306. With MySQL's
default user table granting access to `root@%` (or any wildcard user), an
external attacker who can reach port 3306 can:

1. Attempt brute-force authentication with no lockout by default.
2. Exploit known MySQL 5.5 protocol-level vulnerabilities.
3. Exfiltrate the database contents if any account has a weak or default password.

The Metasploitable 3 scenario includes a trusted application that legitimately
needs remote MySQL access.

## Affected Service
- **Service:** MySQL 5.5
- **Port:** 3306/TCP
- **Config:** /etc/mysql/my.cnf
- **Bind address (vulnerable):** 0.0.0.0

## Vulnerable Configuration
```ini
[mysqld]
bind-address = 0.0.0.0
```

No `/etc/hosts.allow` entry for `mysqld`; all sources permitted.
