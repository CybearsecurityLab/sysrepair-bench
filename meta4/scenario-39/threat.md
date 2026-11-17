# MongoDB 4.4: No Authentication (misconfig)

## Severity
**High** (CVSS 9.1)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
MongoDB 4.4 ships with authentication disabled by default. When the server is
bound to all interfaces, it accepts connections from any client without
requiring credentials. An attacker with network access to the host can connect
directly with a standard client or the MongoDB wire protocol and gain full
read, write, and administrative control over every database, including
listing, modifying, and dropping collections and user data.

This is a misconfiguration, not a code vulnerability, but its impact is
equivalent to a critical authentication bypass: there are no credentials to
steal and no exploit to craft.

## Affected Service
- **Service:** MongoDB 4.4
- **Port:** 27017/TCP
