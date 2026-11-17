# World-Readable System and Access Logs

## Severity
**Medium** (CVSS 5.3)

## CVE
N/A (configuration weakness)

## Description
System authentication and web access logs are world-readable and
world-writable. A web user can inject PHP payloads into logs for
log poisoning attacks. Mirrors Symfonos 4 VulnHub VM.

## Affected Service
- **Service:** rsyslog, Apache
