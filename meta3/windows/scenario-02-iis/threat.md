# IIS Directory Browsing + HTTP TRACE Method Enabled

## Severity
**Medium** (CVSS 5.3)

## CVE
N/A (configuration weakness, CWE-548 directory listing, CWE-16 TRACE / XST)

## Description
Two related IIS misconfigurations are present on the Default Web Site:

1. **Directory browsing** is enabled at the site level. Any request to a folder without a
   default document returns an HTML listing of every file in that
   folder. This leaks file names, timestamps, sizes, and structure, frequently
   including backup files, log exports, and migration dumps that were never meant to
   be publicly enumerated.

2. **HTTP TRACE** has been explicitly allowed by request filtering. TRACE echoes
   the full request, including `Cookie` and `Authorization` headers, back in the
   response body. Combined with an unrelated XSS it enables Cross-Site Tracing (XST)
   to exfiltrate HttpOnly cookies.

Both are standard findings on default / hardened-incorrectly IIS deployments and align
with OpenVAS checks that fire against the upstream Metasploitable3 Windows image.

## Affected Service
- **Service:** `W3SVC` (IIS)
- **Port:** 80/TCP
