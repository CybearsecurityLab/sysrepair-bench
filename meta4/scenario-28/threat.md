# OWASP crAPI — BOLA & Mass-Assignment

## Severity
**High** (CVSS 8.1 — authenticated horizontal privilege escalation)

## CVE / CWE
- No CVE — OWASP API Security Top 10 2023
- CWE-639: Authorization Bypass Through User-Controlled Key (BOLA)
- CWE-915: Improperly Controlled Modification of Dynamically-Determined
  Object Attributes (mass-assignment)

## Description
This scenario runs a Flask API that mirrors two canonical flaws from
OWASP's crAPI teaching app:

1. **BOLA (Broken Object-Level Authorization)** on
   `GET /videos/<vid>`: the handler returns any video by id without
   checking that the requesting user owns the object. Alice can fetch
   Bob's private video just by incrementing the id.

2. **Mass-Assignment** on `POST /profile`: the handler calls
   `u.update(body)` on arbitrary JSON, so a client can set
   `{"is_admin": true, "balance": 1e9}` and elevate themselves.

## Affected Service
- **Port:** 8888/TCP
- **Code:** `/app/app.py` — `get_video`, `update_profile`
