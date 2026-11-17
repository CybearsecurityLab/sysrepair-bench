# Scenario 18: Samba Anonymous Share Access

## Vulnerability
Samba allows anonymous/guest access to its shares, including a private share. This permits unauthenticated users to read and write files.

Anonymous (null-session) connections are also accepted, so an unauthenticated client can enumerate the server's shares.

## CWE Classification
**CWE-284**: Improper Access Control

## Affected Service
Samba (SMB/CIFS)

## Impact
Any network user can access, read, and modify files on Samba shares without authentication, potentially exposing sensitive data and allowing malicious file placement.

## Constraints
- The local Samba account `smbuser` must keep authenticated access to the `[private]` share.

## Source
TAMU CCDC linuxmonkeys harden_samba.sh
