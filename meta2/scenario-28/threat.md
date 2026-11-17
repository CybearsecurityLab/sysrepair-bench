# SSL/TLS Weak Signature Algorithm

## Severity
**Medium** (CVSS 4.0)

## CVE
N/A (cryptographic weakness)

## Description
The SSL/TLS certificates used by the Postfix SMTP server and PostgreSQL database on this
system were signed using the SHA-1 hashing algorithm. SHA-1 is considered cryptographically
weak and has been deprecated by major browser vendors, certificate authorities, and security
standards bodies since 2017.

Practical collision attacks against SHA-1 have been demonstrated (Google's SHAttered attack
in 2017), meaning an attacker with sufficient resources could forge a certificate with the
same SHA-1 signature. This undermines the integrity guarantee of the TLS certificate,
potentially enabling man-in-the-middle attacks where the attacker presents a forged
certificate that appears legitimate.

Modern TLS implementations and security scanners flag SHA-1 signed certificates as
insecure, and some clients may refuse to connect.

## Affected Service
- **Services:** Postfix SMTP Server, PostgreSQL Database
- **Ports:** 25/TCP (SMTP), 5432/TCP (PostgreSQL)
