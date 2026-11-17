# VAmPI: OWASP API Top 10 (Auth/AuthZ)

## Severity
**High** (CVSS 8.1)

## CVE / CWE
- No CVE: OWASP API Security Top 10
- CWE-287: Improper Authentication
- CWE-521: Weak Password Requirements / Weak Secret
- CWE-639: BOLA

## Description
VAmPI's default posture is intentionally vulnerable:

- The application runs in a vulnerable mode that disables a cluster of
  authorization checks on user and book endpoints (BOLA, mass assignment,
  excessive data exposure).
- The JWT signing key is a trivially guessable, wordlist-grade string, so an
  attacker can forge tokens for any user in seconds.

## Affected Service
- **Port:** 5000/TCP
