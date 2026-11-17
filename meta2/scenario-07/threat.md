# PostgreSQL Weak Password

## Severity
**High** (CVSS 9.0)

## CVE
N/A (configuration weakness / weak credentials)

## Description
The PostgreSQL database server on this system is configured with a trivially weak password
for its superuser account, making it guessable via brute-force or dictionary attacks.

Additionally, the server is configured to:
- **Listen on all interfaces**, exposing the database to the entire network.
- **Accept remote password-authenticated connections** from any IP address, allowing remote
  attackers to attempt password-based authentication.

This configuration replicates the Metasploitable 2 PostgreSQL setup. An attacker with
network access to port 5432 can connect as the superuser, gaining full control
over all databases and the ability to:

- Read, modify, or delete any data in any database.
- Create new superuser accounts.
- Execute arbitrary OS commands via database features.
- Read and write files on the server filesystem.

## Affected Service
- **Service:** PostgreSQL 8.3
- **Port:** 5432/TCP
