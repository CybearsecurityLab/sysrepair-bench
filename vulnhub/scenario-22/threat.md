# PHP Execution Enabled in Uploads Directory

## Severity
**Critical** (CVSS 9.8)

## CVE
N/A (configuration weakness)

## Description
Apache allows PHP execution in the uploads directory. An attacker can upload a PHP webshell
disguised with a valid extension and execute it. Mirrors FristiLeaks 1.3 VulnHub VM.

## Affected Service
- **Service:** Apache + PHP
- **Port:** 80/TCP
- **Configuration:** Apache virtual host / .htaccess
