# PHP Command Injection - No Input Sanitization

## Severity
**Critical** (CVSS 10.0)

## CVE
N/A (application vulnerability)

## Description
A PHP script passes user input directly to a system command call without any sanitization
or shell escaping. An attacker can inject arbitrary OS commands.

Mirrors the DC-4 VulnHub VM with web-based command execution.

## Affected Service
- **Service:** Apache + PHP
- **Port:** 80/TCP
