# Apache httpOnly Cookie Information Disclosure

## Severity
**Medium** (CVSS 4.3)

## CVE
N/A (configuration weakness)

## Description
The Apache 2.2 web server on this system does not set the `HttpOnly` and `Secure` flags
on cookies in its responses. Without the `HttpOnly` flag, cookies are accessible to
client-side JavaScript, which means a Cross-Site Scripting (XSS) vulnerability could be
used to steal session cookies and hijack user sessions. Without the `Secure` flag, cookies
may be transmitted over unencrypted HTTP connections, exposing them to network sniffing.

Apache 2.2's default configuration does not add these security flags to cookie headers,
and the tracking cookies it sets lack these protections.

## Affected Service
- **Service:** Apache HTTP Server 2.2
- **Port:** 80/TCP
