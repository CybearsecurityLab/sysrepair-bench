# Metabase 0.46.6: Pre-auth RCE via H2 JDBC Injection (CVE-2023-38646)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2023-38646
- CWE-94: Improper Control of Generation of Code ('Code Injection')

## Description
Metabase versions before 0.46.6.1 / 1.46.6.1 expose a setup validation
endpoint without authentication. This endpoint accepts a JSON body containing
a database connection definition, including a database field that is passed
directly to the H2 JDBC driver as a connection URL.

The H2 JDBC URL supports an initialization parameter that executes arbitrary
SQL on connection, and H2 can fetch and execute a remote script. By chaining
these, an unauthenticated attacker achieves OS command execution through H2.

## Affected Service
- **Service:** Metabase 0.46.6
- **Port:** 3000/TCP

## Constraints
- The affected package must not be upgraded.
