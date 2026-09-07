# Dangerous Sudoers Wildcard Entries

## Severity
**Critical** (CVSS 9.8)

## CVE
N/A (configuration weakness)

## Description
The sudoers file allows user 'bob' to run awk, tar, nmap, and find as root without
password. All of these allow shell escapes (e.g., `sudo awk 'BEGIN {system("/bin/sh")}'`).
Mirrors LinSecurity VulnHub VM.

## Affected Service
- **Service:** sudo
- **Configuration:** /etc/sudoers
