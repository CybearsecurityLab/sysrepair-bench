# Exim4 Binary with SUID Bit

## Severity
**High** (CVSS 7.8)

## CVE
CVE-2016-1531

## Description
The Exim4 mail transfer agent binary has the SUID bit set, allowing any local user to
execute it with root privileges. Combined with known Exim4 vulnerabilities, this enables
local privilege escalation to root.

Mirrors the DC-4 and DC-8 VulnHub VMs.

## Affected Service
- **Service:** Exim4
- **Port:** 25/TCP
- **Binary:** /usr/sbin/exim4
