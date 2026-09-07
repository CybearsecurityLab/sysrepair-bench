# Apache 2.4.49 — Path Traversal + RCE via mod_cgi (CVE-2021-41773)

## Severity
**High** (CVSS 7.5; RCE variant CVSS 9.8)

## CVE / CWE
- CVE-2021-41773
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory

## Description
Apache HTTP Server 2.4.49 introduced a flaw in path normalization that allowed
an attacker to use percent-encoded dot sequences (`%2e`) to escape the document
root and traverse to arbitrary filesystem locations. When `mod_cgi` (or
`mod_cgid`) is also enabled and the target directory has `Options ExecCGI`,
the traversal escalates to unauthenticated remote code execution.

A simple HTTP request such as:
```
GET /cgi-bin/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
```
returns the contents of `/etc/passwd`. When combined with a POST to a cgi-bin
traversal path, an attacker can execute arbitrary shell commands.

This vulnerability was actively exploited within hours of public disclosure.

## Affected Service
- **Service:** Apache HTTP Server 2.4.49 only (fixed in 2.4.51)
- **Port:** 80/TCP
- **Conditions:** `Require all granted` on the root directory AND mod_cgi
  enabled

## Constraints
- Apache must remain at version 2.4.49; upgrading the package is not permitted.
