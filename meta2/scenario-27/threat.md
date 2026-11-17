# SSL/TLS Certificate Expired

## Severity
**Medium** (CVSS 5.0)

## CVE
N/A (operational/configuration issue)

## Description
The SSL/TLS certificates used by the Postfix SMTP server and PostgreSQL database on this
system have expired. Expired certificates cause TLS handshake failures with strict clients,
trigger security warnings, and undermine the trust model of the TLS protocol. When clients
encounter expired certificates, they may:

- Refuse to connect entirely, causing service outages
- Fall back to unencrypted connections, exposing data in transit
- Prompt users to bypass warnings, training them to ignore legitimate security alerts

An attacker could exploit this situation by performing a man-in-the-middle attack, as users
and automated systems may have been conditioned to accept certificate errors, or connections
may have fallen back to unencrypted transport.

## Affected Service
- **Services:** Postfix SMTP Server, PostgreSQL Database
- **Ports:** 25/TCP (SMTP), 5432/TCP (PostgreSQL)
