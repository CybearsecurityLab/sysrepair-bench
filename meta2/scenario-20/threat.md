# Samba MS-RPC Remote Shell Command Execution

## Severity
**Medium** -- CVSS 6.0

## CVE
CVE-2007-2447

## Description
Samba versions 3.0.0 through 3.0.25rc3 are vulnerable to remote command execution via the MS-RPC interface. When the `username map script` option is enabled in `smb.conf`, Samba passes the username supplied by the client through `/bin/sh` for mapping purposes. An attacker can inject shell metacharacters into the username field, achieving arbitrary command execution with the privileges of the Samba daemon (typically root).

The attack is performed by sending a specially crafted username containing shell metacharacters (e.g., backticks or `$(...)` syntax) during an SMB authentication attempt. Ubuntu 8.04 ships Samba 3.0.28a, and while the base version may be patched, the presence of the `username map script` directive creates the vulnerable configuration that scanners flag.

## Affected Service / Port
- **Service:** Samba (SMB/CIFS)
- **Ports:** 139 (NetBIOS), 445 (SMB)

## Vulnerable Version
- Samba 3.0.0 -- 3.0.25rc3 (original vulnerability range)
- Any Samba version with `username map script` configured (configuration vulnerability)
