# ActiveMQ 6.1.0: Jolokia/REST API Exposed Without Authentication (CVE-2024-32114)

## Severity
**High** (CVSS 8.5)

## CVE / CWE
- CVE-2024-32114
- CWE-306: Missing Authentication for Critical Function

## Description
Apache ActiveMQ 6.1.0 ships with the Jolokia JMX-over-HTTP bridge and the
REST messaging API exposed without any authentication requirement. The Jolokia
component allows any unauthenticated HTTP client to read and write JMX
attributes, invoke MBean operations, and query the full broker state. The REST
messaging API allows producing and consuming messages from any queue or topic.

An attacker with network access to port 8161 can:
- Enumerate all JMX MBeans and broker configuration
- Read sensitive configuration values (passwords, LDAP settings, etc.)
- Produce malicious messages to any queue via HTTP POST
- Consume messages intended for legitimate applications

## Affected Service
- **Service:** Apache ActiveMQ Classic 6.1.0
- **Port:** 8161/TCP (Jetty HTTP/Management)
