# Hadoop YARN: Unauthenticated ResourceManager RCE (CWE-306)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- No single CVE (well-known misconfig, widely exploited in the wild)
- CWE-306: Missing Authentication for Critical Function

## Description
The Hadoop YARN ResourceManager exposes a REST API on port 8088. When ACLs are
disabled (the default), there is no authentication or authorisation on this
endpoint, and no Kerberos principal is configured. Any unauthenticated client can:

1. List running applications.
2. Submit a new YARN application with an arbitrary shell command as the
   application master launch command.
3. The NodeManager executes the supplied command as the `yarn` OS user,
   providing unauthenticated remote code execution on every cluster node.

This misconfiguration has been exploited at scale to deploy cryptominers.

## Affected Service
- **Service:** Hadoop YARN ResourceManager
- **Port:** 8088/TCP (REST API)

## Constraints
- Hadoop YARN must not be upgraded to a patched version.
