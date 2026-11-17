# Unprotected Web Application Installer Pages

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-16: Configuration
- CWE-284: Improper Access Control
- OpenVAS: "Unprotected Web App / Device Installers (HTTP)"

## Description
The Drupal and phpMyAdmin installer pages remain reachable over HTTP after
installation is complete. An unauthenticated attacker who discovers these pages
can reinitialize the application database, overwrite site settings, or configure
a new phpMyAdmin installation pointing at arbitrary MySQL credentials.

Affected components:
- The Drupal setup wizard, which allows full database reinitialisation
- The phpMyAdmin configuration generator, which can write a new configuration
  that grants the attacker MySQL root-equivalent access to the management interface

After installation neither Drupal nor phpMyAdmin denies access to their installer
pages, and Apache serves them to all clients without restriction.

## Affected Service
- **Service:** Apache2 + Drupal 7.31 + phpMyAdmin
- **Port:** 80/TCP
