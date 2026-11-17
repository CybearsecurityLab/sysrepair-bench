# Postfix SSL/TLS FREAK & LogJam Export Cipher Vulnerabilities

## Threat Details

**Severity:** Medium
**CVSS Score:** 4.3
**CVE:** CVE-2015-0204 (FREAK), CVE-2015-4000 (LogJam)

## Description

Two related vulnerabilities affect TLS implementations that support legacy EXPORT cipher suites:

1. **FREAK (Factoring RSA Export Keys)**: Allows attackers to force a downgrade to 512-bit RSA_EXPORT cipher suites, which can be factored in hours.

2. **LogJam**: Allows attackers to downgrade TLS connections to 512-bit Diffie-Hellman groups (DHE_EXPORT), enabling decryption of intercepted traffic.

Ubuntu 8.04's OpenSSL 0.9.8g includes EXPORT cipher suites by default, and Postfix TLS is enabled without restricting them.

## Affected Service

- **Service:** Postfix SMTP Server with TLS
- **Port:** 25/tcp
- **Vulnerable Component:** OpenSSL 0.9.8g (Ubuntu 8.04)

## Impact

An active man-in-the-middle attacker can:
- Force a protocol downgrade to weak EXPORT cipher suites
- Factor 512-bit RSA keys or discrete logarithms in reasonable time
- Decrypt intercepted email traffic
- Compromise mail server authentication and confidentiality
