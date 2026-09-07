# Confluence — OGNL Injection via URI (CVE-2022-26134)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-26134
- CWE-917: Improper Neutralization of Special Elements used in an Expression
  Language Statement

## Description
Atlassian Confluence Data Center and Server versions before 7.4.17, 7.13.7,
7.14.3, 7.15.2, 7.16.4, 7.17.4, and 7.18.1 are vulnerable to an
unauthenticated OGNL (Object-Graph Navigation Language) injection. An attacker
can embed an OGNL expression in the HTTP request URI path without any
authentication, causing the expression to be evaluated server-side and
producing arbitrary code execution as the Confluence process user (typically
`confluence` or `root`).

Example exploit request:
```
GET /%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%7D/ HTTP/1.1
```
(URL-decoded: `/${@java.lang.Runtime@getRuntime().exec("id")}/`)

This is a pre-auth RCE with no user interaction. It was actively exploited as
a zero-day before Atlassian published a patch.

## Affected Service
- **Service:** Atlassian Confluence (simulated with Python/Flask on port 8090)
- **Port:** 8090/TCP (Confluence default)
- **Vulnerable configuration:** Direct access to port 8090 with no WAF

## Constraints
- Confluence must not be upgraded; it stays on the vulnerable version.
