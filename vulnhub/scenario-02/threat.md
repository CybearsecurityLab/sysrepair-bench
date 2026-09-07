# SQL Injection in PHP Web App

## Severity
**Critical** (CVSS 9.8)

## CVE
N/A (application vulnerability)

## Description
The web application contains a PHP script that directly concatenates user input into SQL
queries without any sanitization or parameterized queries.

This mirrors the Kioptrix Level 1.1 (Level 2) VulnHub VM which features SQL injection vectors
within a localized web application backed by MySQL.

## Affected Service
- **Service:** Apache HTTP Server + PHP
- **Port:** 80/TCP
- **Binary:** /usr/sbin/apache2
- **Configuration:** /var/www/html/search.php, /etc/apache2/

## Vulnerable Configuration
```php
$q = $_GET["q"];
$result = $db->query("SELECT * FROM users WHERE name = '$q'");
```
