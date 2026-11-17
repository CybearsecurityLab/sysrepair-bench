# SUID-root Helper Binary: Non-root to Root Escalation (CWE-250)

## Severity
**High** (CVSS 8.2)

## CVE / CWE
- CWE-250: Execution with Unnecessary Privileges

## Description
A helper binary on the system is owned by root and carries the **setuid bit**.
The Linux kernel sets the effective UID to the file owner (root) on every
`execve(2)` of a SUID binary, and the helper then raises its real, effective,
and saved IDs to 0 before exec'ing a shell with the caller's arguments.
Consequently any unprivileged user who runs it obtains a **root shell** and can
read root-only files, a direct local privilege escalation. Shipping
unnecessary, privilege-bearing executables that any user can invoke is the
classic CWE-250 weakness.

## Affected Service
- **Component:** a setuid-root helper binary runnable by any user
