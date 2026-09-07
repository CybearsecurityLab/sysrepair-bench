# Apache Airflow 1.10.12 — Default Session Secret Key (CVE-2020-17526)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CVE-2020-17526
- CWE-1188: Insecure Default Initialization of Resource

## Description
Apache Airflow 1.10.12 ships with a default `secret_key = temporary_key` in
`airflow.cfg`. This key is used by the Flask web framework to sign session cookies.
Because the value is publicly documented and well-known, an attacker can use the
`itsdangerous` library to craft a valid, signed session cookie with an arbitrary
user identity — including admin — and submit it to the Airflow webserver.

This allows full authentication bypass with no brute-force required. An attacker
with network access to port 8080 can gain admin access to all DAGs, connections
(which may contain database credentials), variables, and can trigger arbitrary
workflow executions.

## Affected Service
- **Service:** Apache Airflow 1.10.12
- **Port:** 8080/TCP
- **Vulnerable file:** `$AIRFLOW_HOME/airflow.cfg`

## Vulnerable Configuration
- `secret_key = temporary_key` in the `[webserver]` section of `airflow.cfg`
