# World-Writable Root-Trusted Resource (`/etc/ld.so.preload`) — CWE-250

## Severity
**High** (CVSS 8.1)

## CVE / CWE
- CWE-250: Execution with Unnecessary Privileges (missing Mandatory Access
  Control on a root-trusted resource)

## Description
`/etc/ld.so.preload` is read by the dynamic linker (`ld.so`) before **every**
dynamically linked program starts, and every library path listed in it is loaded
into that process — including processes that run **as root**. In this scenario
the file is root-owned but **world-writable** (mode `0666`), so any unprivileged
user can append a path to it:

```
su -s /bin/sh appuser -c 'echo /tmp/evil.so > /etc/ld.so.preload'
```

Once written, the next root process to start will load the attacker-controlled
library with root privileges — a classic local privilege-escalation primitive.
The weakness is the missing access control on a security-sensitive,
root-**trusted** file: a resource the system implicitly trusts is left writable
by untrusted (non-root) code.

## Affected Service
- **File:** `/etc/ld.so.preload` (root-owned, mode `0666` — world-writable)
- **Trusting consumer:** the dynamic loader `ld.so`, on every program start

## Vulnerable Configuration
- `/etc/ld.so.preload` mode `0666` (any user may write)
- An unprivileged user (`appuser`) can plant a preload library path
