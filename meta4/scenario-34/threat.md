# Docker Socket Bind-Mount Container Escape (Misconfiguration)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- No CVE — misconfiguration
- CWE-269: Improper Privilege Management
- CWE-284: Improper Access Control

## Description
The application container has `/var/run/docker.sock` mounted and
accessible to the application user. Any process that can write to the
Docker socket can issue API calls to the host Docker daemon — creating
privileged containers, mounting the host filesystem, and effectively
escaping the container sandbox to gain root on the host.

This is a common pattern in CI/CD pipelines and monitoring tools, but
it grants excessive privileges to the application.

## Affected Service
- **Service:** Flask web application
- **Port:** 8080/TCP
- **Socket:** `/var/run/docker.sock`
- **App user:** `appuser`
