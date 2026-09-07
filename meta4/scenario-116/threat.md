# Rsync Daemon — No Authentication / No ACL (misconfig)

## Severity
**Critical** (CVSS 9.1)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
When the rsync daemon is configured with a module that exposes a path (such
as `/`) without `auth users` and without a `secrets file`, any client that can
reach port 873 can:

- **Read** any file on the exposed path (including `/etc/passwd`,
  `/etc/shadow`, SSH private keys, application secrets).
- **Write** arbitrary files anywhere under the module path (e.g., drop a
  cron job, overwrite `/etc/cron.d/`, plant SSH authorized_keys).

No credentials, no exploit, no CVE needed — the service simply has no access
control configured. A single rsync command:

```
rsync rsync://target/data/etc/passwd /tmp/stolen-passwd
```

succeeds without prompting for a password and returns the full content of
`/etc/passwd`.

## Affected Service
- **Service:** rsync daemon (any version)
- **Port:** 873/TCP
- **Vulnerable configuration:** Module in `/etc/rsyncd.conf` without
  `auth users` or `secrets file`
