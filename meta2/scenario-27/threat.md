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
- **Certificate Files:**
  - /etc/ssl/certs/expired.crt
  - /etc/ssl/private/expired.key
  - /etc/postgresql/8.3/main/server.crt
  - /etc/postgresql/8.3/main/server.key

## Vulnerable Configuration
The SSL certificates were generated with a very short validity period and have expired:

```
# Certificate generated with -days 0 or -days 1 (already expired or about to expire)
openssl req -x509 -newkey rsa:2048 -keyout expired.key -out expired.crt \
    -days 0 -nodes -subj "/CN=localhost"

# Postfix configured with expired cert
smtpd_tls_cert_file = /etc/ssl/certs/expired.crt
smtpd_tls_key_file = /etc/ssl/private/expired.key

# PostgreSQL configured with expired cert
ssl = true
# server.crt and server.key are copies of the expired certificate
```
