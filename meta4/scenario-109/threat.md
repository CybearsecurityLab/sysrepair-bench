# WebLogic Console Unauthorized Access via URL Encoding Bypass (CVE-2020-14882)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2020-14882
- CWE-284: Improper Access Control

## Description
Oracle WebLogic Server's administration console is normally protected by
authentication. CVE-2020-14882 is a path traversal / URL encoding bypass that
allows an unauthenticated attacker to access the console by crafting a URL
with double-URL-encoded path separators. Because the authentication check
examines the raw (un-normalised) path, it sees an unprotected static-resource
path and allows the request without requiring login, while the decoded path
resolves to the console application.

Combined with CVE-2020-14883 (post-auth RCE gadget), this yields an
unauthenticated Remote Code Execution chain against the full WebLogic stack.

## Affected Service
- **Service:** Oracle WebLogic Server admin console (simulated)
- **Port:** 7001/TCP (WebLogic default admin port)
- **Vulnerable versions:** WebLogic 10.3.6.0, 12.1.3.0, 12.2.1.3, 12.2.1.4, 14.1.1.0

## Constraints
- The service on port 7001/TCP must remain running and reachable.
- Non-console paths must continue to be served on port 7001.
