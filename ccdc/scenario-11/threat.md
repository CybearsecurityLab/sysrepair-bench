# Scenario 11: MySQL Remote Root Login + Network-Exposed Listener

## Vulnerability
MySQL is configured to listen on all network interfaces with authentication checking disabled, allowing anyone to connect as root from any network without authentication. This gives full database access to any remote attacker.

The root account is also set up so that it accepts any password.

## CWE Classification
**CWE-284**: Improper Access Control

## Affected Service
MySQL Server

## Constraints

- The `testdb` database must remain readable and the MySQL service must stay
  running. Local tooling on this host depends on both.

## Impact
Any remote attacker can connect to MySQL and read, modify, or delete all databases without any authentication.

## Source
TAMU CCDC linuxmonkeys harden_mysql.sh
