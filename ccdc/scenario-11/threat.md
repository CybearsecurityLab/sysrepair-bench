# Scenario 11: MySQL Remote Root Login + No bind-address

## Vulnerability
MySQL is configured to listen on all interfaces (`bind-address = 0.0.0.0`) with `skip-grant-tables` enabled, allowing anyone to connect as root from any network without authentication. This gives full database access to any remote attacker.

The image also ships `root@localhost` on `auth_socket`, which authenticates by
operating-system user and therefore accepts ANY password.

## CWE Classification
**CWE-284**: Improper Access Control

## Affected Service
MySQL Server

## Configuration File
`/etc/mysql/mysql.conf.d/zzz-vulnerable.cnf` or `/etc/mysql/my.cnf`

## Vulnerable Settings
```
bind-address = 0.0.0.0
skip-grant-tables
```

## Constraints

- The `testdb` database must remain readable and the MySQL service must stay
  running. Local tooling on this host depends on both.

## Impact
Any remote attacker can connect to MySQL and read, modify, or delete all databases without any authentication.

## Source
TAMU CCDC linuxmonkeys harden_mysql.sh
