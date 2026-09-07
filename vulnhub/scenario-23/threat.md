# Custom SUID Binary with PATH Hijacking

## Severity
**High** (CVSS 7.8)

## CVE
N/A (application weakness)

## Description
A custom SUID binary calls system commands (curl) without absolute paths, enabling PATH
hijacking. An attacker can create a malicious `curl` in their PATH to execute arbitrary
code as root. Mirrors Symfonos 1 VulnHub VM.

## Affected Service
- **Binary:** /usr/local/bin/statuscheck (SUID)
