# Binary With Dangerous Linux File Capability (CAP_SYS_PTRACE), CWE-250

## Severity
**High** (CVSS 7.8)

## CVE / CWE
- CWE-250: Execution with Unnecessary Privileges

## Description
A helper binary on the system carries a dangerous Linux **file capability**,
CAP_SYS_PTRACE. Linux file capabilities are stored in an extended attribute on
the executable and are enforced by the kernel on every `execve(2)`: any user
who runs the binary, including a fully unprivileged one, receives
`CAP_SYS_PTRACE` in that process's effective set.

With `CAP_SYS_PTRACE` an unprivileged attacker can:

1. Read another (root-owned) process's memory map and memory, access the
   kernel would otherwise deny.
2. Attach to and manipulate root-owned processes, harvest secrets from their
   address space, or inject code, a local privilege-escalation primitive.

## Affected Service
- **Service:** a local helper binary carrying a Linux file capability
