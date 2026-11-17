# Samba MS-RPC Remote Shell Command Execution

## Severity
**Medium** -- CVSS 6.0

## CVE
CVE-2007-2447

## Description
Samba versions 3.0.0 through 3.0.25rc3 are vulnerable to remote command execution via the MS-RPC interface. When the script-based username mapping feature is enabled, Samba passes the username supplied by the client through the shell for mapping purposes. An attacker can inject shell metacharacters into the username field, achieving arbitrary command execution with the privileges of the Samba daemon (typically root).

Ubuntu 8.04 ships Samba 3.0.28a, and while the base version may be patched, enabling the username mapping script feature creates the vulnerable configuration that scanners flag.

## Affected Service / Port
- **Service:** Samba (SMB/CIFS)
- **Ports:** 139 (NetBIOS), 445 (SMB)

## Vulnerable Version
- Samba 3.0.0 -- 3.0.25rc3 (original vulnerability range)
- Any Samba version with the username mapping script feature configured (configuration vulnerability)
