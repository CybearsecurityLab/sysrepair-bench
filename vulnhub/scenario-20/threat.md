# Apache CGI Shellshock Vulnerability

## Severity
**Critical** (CVSS 10.0)

## CVE
CVE-2014-6271

## Description
Apache CGI scripts use Bash to process requests. If the Bash binary is vulnerable to
Shellshock, environment variables from HTTP headers can be evaluated as executable code.
Mirrors SickOs 1.1 VulnHub VM.

The image ships a Shellshock-vulnerable `bash 4.3.0` built from source at `/bin/bash`, while
the distro's patched bash package is still recorded in dpkg.

## Affected Service
- **Service:** Apache + mod_cgi + Bash
- **Port:** 80/TCP
- **Configuration:** /usr/lib/cgi-bin/
