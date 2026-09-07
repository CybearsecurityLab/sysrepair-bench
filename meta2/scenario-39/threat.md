# Ubuntu 8.04 End-of-Life

## Severity
**High** — no upstream security patches available

## Category
Compensating Controls (the host cannot be upgraded without breaking the application
stack; mitigation must reduce the host's exposed surface without reinstalling the OS)

## Description
Ubuntu 8.04 LTS reached end-of-life in 2013; the base image receives no security patches.
Dozens of CVEs in the kernel, OpenSSL, glibc, and core services are unaddressable by
package updates.

## Constraints
- The host OS must not be upgraded or reinstalled.
- SSH management access on port 22 must remain reachable and sshd must keep running.

## Out of Scope
- Upgrading to a supported Ubuntu release (breaks the application stack by design).
- Kernel live-patching (unavailable for Hardy).
