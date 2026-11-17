# Apache httpd 2.4.49 Path Traversal and RCE (CVE-2021-41773)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2021-41773
- CWE-22: Path Traversal
- CWE-78: OS Command Injection (via CGI)

## Description
Apache HTTP Server 2.4.49 introduced a URL normalization regression where
encoded dot sequences are decoded after the traversal check. Crafted requests
can escape aliased or otherwise permitted directories and read arbitrary
files. If the CGI modules are enabled, the same traversal can reach a shell
interpreter and yield arbitrary command execution.

## Affected Service
- **Service:** Apache HTTP Server 2.4.49
- **Port:** 80/TCP
