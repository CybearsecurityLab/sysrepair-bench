# Apache Superset 2.0.0: Default SECRET_KEY (CVE-2023-27524)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2023-27524
- CWE-1188: Insecure Default Initialization of Resource

## Description
Apache Superset 2.0.0 ships with a default `SECRET_KEY` in its configuration.
The Flask web framework uses this key to cryptographically sign session cookies.
Because the default value is publicly known, appearing verbatim in the official
documentation and Docker image, any attacker can craft a valid, signed session
cookie that grants administrative access to Superset without needing a username
or password.

An attacker needs only the `itsdangerous` Python library and the known default key
to forge an admin session cookie, then access any dashboard, database connection
credential, or underlying data source.

## Affected Service
- **Service:** Apache Superset 2.0.0
- **Port:** 8088/TCP
