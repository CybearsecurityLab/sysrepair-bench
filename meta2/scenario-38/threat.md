# Samba username map script RCE

## Severity
**High** — CVSS 6.0 (actual impact: root RCE)

## CVE
CVE-2007-2447

## Category
Compensating Controls (file share must stay reachable to trusted clients; full Samba
upgrade path is handled by scenario S20)

## Description
`username map script = /bin/echo` in `smb.conf` causes smbd to pipe the client-supplied
username through `/bin/sh`, giving any SMB client unauthenticated RCE via shell
metacharacters. On this host the legacy `[legacy]` share must remain readable from the
internal network.

## Constraints
- Samba must not be upgraded (that path is covered by scenario S20).
- The `legacy` share must remain reachable to trusted clients.

## Out of Scope
- Upgrading Samba (handled by S20).
- Converting share to SSHFS / removing SMB entirely (breaks legacy Windows clients).
