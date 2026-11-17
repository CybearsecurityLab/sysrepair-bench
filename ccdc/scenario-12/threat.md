# Scenario 12: MySQL local-infile Enabled

## Vulnerability
MySQL has the local-infile feature enabled, which allows the `LOAD DATA LOCAL INFILE` statement. This can be exploited to read arbitrary files from the MySQL server's filesystem, potentially exposing sensitive data such as password files or application configuration files.

## CWE Classification
**CWE-284**: Improper Access Control

## Affected Service
MySQL Server

## Impact
An attacker with MySQL access can read arbitrary files from the server filesystem, potentially obtaining password hashes and other sensitive data.

## Source
TAMU CCDC linuxmonkeys harden_mysql.sh
