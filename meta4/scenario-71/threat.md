# SUID-root Helper Binary — Non-root to Root Escalation (CWE-250)

## Severity
**High** (CVSS 8.2)

## CVE / CWE
- CWE-250: Execution with Unnecessary Privileges

## Description
A helper binary at `/usr/local/bin/suidhelper` is owned by root and carries the
**setuid bit** (`chmod 4755`). The Linux kernel sets the effective UID to the
file owner (root) on every `execve(2)` of a SUID binary, and the helper then
calls `setuid(0)`/`setgid(0)` to make its real, effective, and saved IDs all 0
before exec'ing `/bin/sh` with the caller's arguments. Consequently any
unprivileged user who runs it obtains a **root shell**:

```
su -s /bin/sh appuser -c '/usr/local/bin/suidhelper -c "cat /etc/shadow"'
```

reads `/etc/shadow` (mode 640, `root:shadow`) even though `appuser` has no rights
to it — a direct local privilege escalation. Shipping unnecessary,
privilege-bearing executables that any user can invoke is the classic CWE-250
weakness.

## Affected Service
- **Binary:** `/usr/local/bin/suidhelper` (owned by root, mode `4755`)
- **Sensitive target reached:** `/etc/shadow` (and any root-only resource)

## Vulnerable Configuration
- `chmod 4755 /usr/local/bin/suidhelper` (setuid-root, world-executable)
- An unprivileged user (`appuser`) can exec it to run commands as root
