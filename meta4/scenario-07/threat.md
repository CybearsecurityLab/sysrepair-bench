# Apache Tomcat Partial-PUT Deserialization RCE (CVE-2025-24813)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2025-24813
- CWE-502: Deserialization of Untrusted Data

## Description
Tomcat 9.0.0 to 9.0.98 (and corresponding 10.1.x / 11.0.x ranges) support
partial PUT uploads. When writes are enabled on the default servlet AND the
application uses a persistent file-backed session store, content uploaded by
an attacker through a partial PUT can land at a location that Tomcat later
treats as a session file. The session manager deserializes that
attacker-controlled file on session load, executing code with Tomcat's
privileges.

## Affected Service
- **Service:** Apache Tomcat 9.0.98
- **Port:** 8080/TCP
