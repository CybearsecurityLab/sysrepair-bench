# MySQL Unrestricted File Import and Export

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness)

## Description
MySQL/MariaDB places no restriction on the directories the database may read from and write
to, allowing the database to read and write files anywhere on the filesystem. Combined with a
database user having the FILE privilege, an attacker can use `SELECT ... INTO OUTFILE`
to write arbitrary files (such as webshells) or `LOAD DATA INFILE` to read sensitive
system files.

This mirrors the Kioptrix Level 1.3 (Level 4) VulnHub VM with vulnerable MySQL OUTFILE
configurations.

## Affected Service
- **Service:** MariaDB/MySQL
- **Port:** 3306/TCP
