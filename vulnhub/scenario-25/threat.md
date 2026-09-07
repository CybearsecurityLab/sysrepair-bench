# CGI-bin Directory with Lax Permissions

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness)

## Description
The CGI-bin directory (/usr/lib/cgi-bin/) has world-writable (777) permissions, allowing
any user to place and execute arbitrary CGI scripts. Mirrors Symfonos 3 VulnHub VM.

## Affected Service
- **Service:** Apache + mod_cgi
- **Port:** 80/TCP
- **Configuration:** /usr/lib/cgi-bin/
