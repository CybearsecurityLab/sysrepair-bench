# Apache 2.4.49: Path Traversal and RCE via mod_cgi (CVE-2021-41773)

## Severity
**High** (CVSS 7.5; RCE variant CVSS 9.8)

## CVE / CWE
- CVE-2021-41773
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory

## Description
Apache HTTP Server 2.4.49 introduced a flaw in path normalization that allowed
an attacker to use percent-encoded dot sequences to escape the document
root and traverse to arbitrary filesystem locations. When `mod_cgi` (or
`mod_cgid`) is also enabled and CGI execution is permitted for the target
directory, the traversal escalates to unauthenticated remote code execution.

An unauthenticated attacker can read arbitrary files and, through the CGI
directory, execute arbitrary shell commands.

This vulnerability was actively exploited within hours of public disclosure.

## Affected Service
- **Service:** Apache HTTP Server 2.4.49 only
- **Port:** 80/TCP

## Constraints
- Apache must remain at version 2.4.49; upgrading the package is not permitted.
