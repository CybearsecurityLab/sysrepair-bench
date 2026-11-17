# OWASP crAPI: BOLA and Mass-Assignment

## Severity
**High** (CVSS 8.1, authenticated horizontal privilege escalation)

## CVE / CWE
- No CVE: OWASP API Security Top 10 2023
- CWE-639: Authorization Bypass Through User-Controlled Key (BOLA)
- CWE-915: Improperly Controlled Modification of Dynamically-Determined
  Object Attributes (mass-assignment)

## Description
This scenario runs a Flask API that mirrors two canonical flaws from
OWASP's crAPI teaching app:

1. **BOLA (Broken Object-Level Authorization)** on the video retrieval
   handler: it returns any video by id without checking that the requesting
   user owns the object, so one user can fetch another user's private video
   just by incrementing the id.

2. **Mass-Assignment** on the profile update handler: it applies the
   client's arbitrary JSON body directly to the user record, so a client can
   set privileged attributes and elevate themselves.

## Affected Service
- **Port:** 8888/TCP
