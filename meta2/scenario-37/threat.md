# Java RMI Registry + DistCC Open to Internet

## Severity
**Critical** — CVSS 10.0 (Java RMI CVE-2011-3556 class-loader RCE) / 9.3 (DistCC CVE-2004-2687)

## Category
Compensating Controls (both services must remain reachable *internally* for the
build-farm / JVM orchestration that depends on them, but exposure to untrusted networks
must be eliminated)

## Description
DistCC (3632) is configured with `--allow 0.0.0.0/0`, exposing the fork-and-exec build
helper to the Internet; Java RMI registry (1099) is similarly bound to all interfaces,
allowing remote class loading. Removing these services would break the build pipeline and
the management JVM.

## Affected Ports
- 1099/TCP — Java RMI Registry
- 3632/TCP — DistCC daemon

## Constraints
- Neither DistCC nor the Java RMI registry may be removed or stopped; both must keep
  listening on their ports.
- The trusted build subnet `10.10.0.0/24` must retain access to ports 1099 and 3632.

## Out of Scope
- Removing DistCC or RMI (breaks build farm / JVM orchestration).
- Upgrading RMI to post-CVE JDK (out of reach on Ubuntu 8.04).
