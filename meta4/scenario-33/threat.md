# Docker Daemon Unauthenticated TCP Access (Misconfiguration)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- No CVE — misconfiguration
- CWE-284: Improper Access Control
- CWE-319: Cleartext Transmission of Sensitive Information

## Description
The Docker daemon is configured to listen on `tcp://0.0.0.0:2375`
without TLS authentication. This means any network client can issue
Docker API requests — creating, starting, stopping, or deleting
containers, mounting host filesystems, and effectively gaining root
access to the Docker host. This is a common cloud misconfiguration
that has led to widespread crypto-mining and data exfiltration.

## Affected Service
- **Service:** Docker daemon (dockerd)
- **Port:** 2375/TCP (unauthenticated API)
- **Config:** `/etc/docker/daemon.json` and/or dockerd CLI flags
