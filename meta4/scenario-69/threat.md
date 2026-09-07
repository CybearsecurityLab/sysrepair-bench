# Binary With Dangerous Linux File Capability (cap_sys_ptrace) — CWE-250

## Severity
**High** (CVSS 7.8)

## CVE / CWE
- CWE-250: Execution with Unnecessary Privileges

## Description
A helper binary on the system carries the `cap_sys_ptrace=ep` **file
capability**. Linux file capabilities are stored in the `security.capability`
extended attribute on the executable and are enforced by the kernel on every
`execve(2)`: any user who runs the binary — including a fully unprivileged one —
receives `CAP_SYS_PTRACE` in that process's effective set.

With `CAP_SYS_PTRACE` an unprivileged attacker can:

1. Read another (root-owned) process's memory map and memory via
   `/proc/<pid>/maps` and `ptrace(2)` — access the kernel would otherwise deny
   with `EACCES`.
2. Attach to and manipulate root-owned processes, harvest secrets from their
   address space, or inject code — a local privilege-escalation primitive.

Here the binary is `/opt/ptrace-helper` (a copy of `/bin/cat`) with
`cap_sys_ptrace+ep`. An unprivileged user can run
`/opt/ptrace-helper /proc/1/maps` and read a root process's memory layout — proof
the capability is live and abusable.

## Affected Service
- **Binary:** `/opt/ptrace-helper` (`cap_sys_ptrace=ep` file capability)
- **Kernel bit:** CAP_SYS_PTRACE = bit 19

## Vulnerable Configuration
- `setcap cap_sys_ptrace+ep /opt/ptrace-helper` on the on-disk executable
- An unprivileged user (`nobody`) can use it to read `/proc/1/maps`
