# Scenario 20: WordPress File Editor Enabled

## Vulnerability
WordPress allows authenticated administrators to edit PHP files (themes and plugins) directly through the WordPress admin panel, enabling code injection if an admin account is compromised.

The WordPress configuration file also holds the database credentials and is readable by any local account on the host.

## CWE Classification
- **CWE-94**: Improper Control of Generation of Code (Code Injection)
- **CWE-732**: Incorrect Permission Assignment for Critical Resource

## Affected Service
WordPress (via Apache/PHP)

## Impact
An attacker who gains admin access to WordPress can inject arbitrary PHP code into theme or plugin files, achieving remote code execution on the server.

## Source
TAMU CCDC linuxmonkeys harden_wordpress.sh
