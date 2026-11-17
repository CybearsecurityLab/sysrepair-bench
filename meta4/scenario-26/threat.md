# Docker Socket and Privileged Container Escape

## Severity
**Critical** (architectural; CVSS ≈ 9.9 when reachable)

## CVE / CWE
- No CVE: documented-by-design weakness
- CWE-250: Execution with Unnecessary Privileges
- CWE-269: Improper Privilege Management

## Description
Mounting the Docker daemon socket into a container gives processes inside the
container full control over the Docker daemon, equivalent to root on the host.
A compromised app can start a new container with the host filesystem mounted
and obtain a shell on the host.

Running the container in privileged mode disables nearly all container
isolation: the container gets all Linux capabilities, unrestricted device
access, and can remount the host filesystem. Either setting independently voids
the security boundary; this scenario ships both in its container deployment
definition.

This is a **compensating-controls** scenario: neither setting has a
"patched version."

## Affected Service
- **Service:** containerised application deployed with Docker Compose
