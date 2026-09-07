# GNU Screen SUID Bit Set

## Severity
**High** (CVSS 7.8)

## CVE
CVE-2017-5618

## Description
GNU Screen has the SUID bit set, allowing local users to escalate privileges to root.
CVE-2017-5618 allows local users to create and manipulate files in /var/run/screen,
leading to root privilege escalation.

Mirrors the DC-5 VulnHub VM.

## Affected Service
- **Service:** GNU Screen
- **Binary:** /usr/bin/screen
