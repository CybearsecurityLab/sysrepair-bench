# Apache httpd 2.4.50 Double-Encoded Traversal Bypass (CVE-2021-42013)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2021-42013
- CWE-22: Path Traversal

## Description
Apache httpd 2.4.50 was the initial fix for CVE-2021-41773 but the
normalization check missed double-encoded traversal sequences. Such
sequences are decoded after the traversal check, re-enabling arbitrary file
read and (with the CGI modules loaded) arbitrary command execution.

## Affected Service
- **Service:** Apache HTTP Server 2.4.50
- **Port:** 80/TCP
