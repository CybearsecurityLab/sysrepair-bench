# MySQL Root Empty Password

## Severity
**High** (CVSS 9.0)

## CVE
N/A (configuration weakness)

## Description
The MySQL database server on this system is configured with an empty password for the root
account and is listening on all network interfaces. This is a critical security
misconfiguration that replicates the Metasploitable 2 MySQL setup.

An attacker with network access to port 3306 can connect to the MySQL server as root without
any password, gaining full administrative control over all databases. This allows an attacker
to:

- **Read all data:** Access every database, table, and record on the server.
- **Modify data:** Insert, update, or delete any data, including user credentials.
- **Execute system commands:** Using MySQL features to read/write files or execute OS
  commands.
- **Escalate privileges:** Create new database users, grant privileges, or use MySQL
  as a pivot point for further attacks on the system.

## Affected Service
- **Service:** MySQL Server
- **Port:** 3306/TCP
