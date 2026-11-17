# ProFTPD 1.3.5 mod_copy Arbitrary File Copy

## Severity
**Critical** (CVSS 10.0)

## CVE
CVE-2015-3306

## Description
ProFTPD 1.3.5 ships with `mod_copy` enabled by default. The `mod_copy` module
implements the `SITE CPFR` (copy from) and `SITE CPTO` (copy to) FTP commands,
which allow any unauthenticated client to read and write arbitrary files on the
server filesystem. Because ProFTPD runs as root or a service account with broad
filesystem access, an attacker can read sensitive system files or SSH private
keys, place attacker-controlled content in the web root to execute arbitrary
commands, and overwrite critical system files.

No authentication is required. The commands are processed in the pre-authentication
context of the FTP session.

## Affected Service
- **Service:** ProFTPD 1.3.5
- **Port:** 21/TCP
- **Module:** mod_copy
