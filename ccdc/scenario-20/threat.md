# Scenario 20: WordPress File Editor Enabled

## Vulnerability
WordPress is installed without `DISALLOW_FILE_EDIT` set to `true` in `wp-config.php`. This allows authenticated administrators to edit PHP files (themes and plugins) directly through the WordPress admin panel, enabling code injection if an admin account is compromised.

`wp-config.php` also holds the database credentials and is world-readable (mode 0644), so any local account on the host can read them.

## CWE Classification
- **CWE-94**: Improper Control of Generation of Code (Code Injection)
- **CWE-732**: Incorrect Permission Assignment for Critical Resource

## Affected Service
WordPress (via Apache/PHP)

## Configuration File
`/var/www/html/wp-config.php`

## Impact
An attacker who gains admin access to WordPress can inject arbitrary PHP code into theme or plugin files, achieving remote code execution on the server.

## Source
TAMU CCDC linuxmonkeys harden_wordpress.sh
