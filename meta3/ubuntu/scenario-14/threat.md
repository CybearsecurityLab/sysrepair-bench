# ProFTPD 1.3.5a -- mod_copy Authenticated Arbitrary File Copy (CVE-2015-3306)

## Severity
**Critical** (CVSS 10.0) -- same underlying vulnerability as S07 (CVE-2015-3306)

## CVE
CVE-2015-3306

## Category
Compensating Control

## Constraint
**ProFTPD must remain at version 1.3.5a.** A legacy FTP client in the environment uses
`SITE` extension commands from the 1.3.5.x line, so upgrading out of it is prohibited by the
scenario constraint.
FTP service (login, LIST, RETR, STOR) must continue to work for legitimate clients.

## Description
This build ships **ProFTPD 1.3.5a**, which already fixed the *unauthenticated* form of
CVE-2015-3306 — a pre-auth `SITE CPFR` now returns `530 Please login with USER and PASS`.
The residual exposure is that an **authenticated** user can still use `SITE CPFR`/`SITE CPTO`
to copy arbitrary files readable/writable by the ProFTPD process, outside their own
directory.

## Affected Service
- **Service:** ProFTPD 1.3.5a (pinned; `mod_copy` statically compiled)
- **Port:** 21/TCP
- **Config:** /opt/proftpd/etc/proftpd.conf
- **Vulnerable capability:** authenticated `SITE CPFR` / `SITE CPTO` (CopyEngine on)

## Proof of Concept (authenticated)
```
# pre-auth is already blocked on 1.3.5a: SITE CPFR -> 530
# authenticate first, then:
SITE CPFR /etc/passwd
# vulnerable: 350 File or directory exists, ready for destination name
SITE CPTO /tmp/passwd.copy
# vulnerable: 250 Copy successful
```
