# World-Writable Root-Trusted Resource (dynamic loader preload list), CWE-250

## Severity
**High** (CVSS 8.1)

## CVE / CWE
- CWE-250: Execution with Unnecessary Privileges (missing Mandatory Access
  Control on a root-trusted resource)

## Description
The dynamic linker's system-wide preload list is read before **every**
dynamically linked program starts, and every library path listed in it is loaded
into that process, including processes that run **as root**. In this scenario
the file is root-owned but **world-writable**, so any unprivileged user can
append a library path to it.

Once written, the next root process to start will load the attacker-controlled
library with root privileges, a classic local privilege-escalation primitive.
The weakness is the missing access control on a security-sensitive,
root-**trusted** file: a resource the system implicitly trusts is left writable
by untrusted (non-root) code.

## Affected Service
- **Trusting consumer:** the dynamic loader `ld.so`, on every program start
