# Scenario 20: WordPress File Editor Enabled

## Vulnerability
WordPress is installed without `DISALLOW_FILE_EDIT` set to `true` in `wp-config.php`. This allows authenticated administrators to edit PHP files (themes and plugins) directly through the WordPress admin panel, enabling code injection if an admin account is compromised.

## CWE Classification
**CWE-94**: Improper Control of Generation of Code (Code Injection)

## Affected Service
WordPress (via Apache/PHP)

## Configuration File
`/var/www/html/wp-config.php`

## Impact
An attacker who gains admin access to WordPress can inject arbitrary PHP code into theme or plugin files, achieving remote code execution on the server.

## Source
TAMU CCDC linuxmonkeys harden_wordpress.sh
