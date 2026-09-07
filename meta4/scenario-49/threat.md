# ActiveMQ 6.1.0 — Jolokia/REST API Exposed Without Authentication (CVE-2024-32114)

## Severity
**High** (CVSS 8.5)

## CVE / CWE
- CVE-2024-32114
- CWE-306: Missing Authentication for Critical Function

## Description
Apache ActiveMQ 6.1.0 ships with the Jolokia JMX-over-HTTP bridge and the
REST messaging API exposed under the `/api/` context path without any
authentication requirement. The Jolokia endpoint allows any unauthenticated
HTTP client to read and write JMX attributes, invoke MBean operations, and
query the full broker state. The REST API (`/api/message`) allows producing
and consuming messages from any queue or topic.

An attacker with network access to port 8161 can:
- Enumerate all JMX MBeans and broker configuration via `/api/jolokia/list`
- Read sensitive configuration values (passwords, LDAP settings, etc.)
- Produce malicious messages to any queue via HTTP POST
- Consume messages intended for legitimate applications

No credentials are required:
```
curl http://<host>:8161/api/jolokia/read/java.lang:type=Memory/HeapMemoryUsage
```

## Affected Service
- **Service:** Apache ActiveMQ Classic 6.1.0
- **Port:** 8161/TCP (Jetty HTTP/Management)
- **Vulnerable endpoint:** `/api/` (Jolokia + REST messaging)

## Vulnerable Configuration
- Default `jetty.xml` does not enforce authentication on the `/api/` context
- `webapps/api/` WAR deployed without a `security-constraint` requiring credentials
