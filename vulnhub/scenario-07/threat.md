# Drupal 7 Drupalgeddon SQL Injection

## Severity
**Critical** (CVSS 10.0)

## CVE
CVE-2014-3704

## Description
The Drupal database abstraction layer in includes/database/database.inc contains a SQL
injection vulnerability in the expandArguments() function. Array keys from user input are
not sanitized before being used in SQL queries, allowing unauthenticated remote attackers
to execute arbitrary SQL commands.

This mirrors the DC-1 VulnHub VM running Drupal 7.x.

## Affected Service
- **Service:** Apache + Drupal 7
- **Port:** 80/TCP
- **Configuration:** /var/www/html/includes/database/database.inc
