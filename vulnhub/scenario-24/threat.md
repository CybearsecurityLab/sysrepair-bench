# MySQL User with FILE and SUPER Privileges

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness)

## Description
The web application database user has dangerous FILE and SUPER privileges. FILE allows
reading/writing arbitrary files. SUPER allows various admin operations.
Mirrors Symfonos 2 VulnHub VM.

## Affected Service
- **Service:** MariaDB
- **Port:** 3306/TCP
