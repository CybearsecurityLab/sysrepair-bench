# Scenario 09: Nginx Version Disclosure

## Vulnerability
Nginx is configured to include its version number in HTTP response headers (Server header) and default error pages. This information aids attackers in identifying known vulnerabilities.

## CWE Classification
**CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor

## Affected Service
Nginx

## Impact
Version disclosure helps attackers identify specific CVEs and exploits applicable to the running version of Nginx.

## Source
TAMU CCDC linuxmonkeys harden_nginx.sh
