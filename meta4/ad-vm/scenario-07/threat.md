# Scenario 07 - ADCS ESC1 (ENROLLEE_SUPPLIES_SUBJECT)

**Severity:** Critical
**Category:** Configuration Hardening
**CVE:** n/a (misconfiguration; SpecterOps ESC1 documented technique)
**CWE:** CWE-284 (improper access control)
**Compensating controls accepted:** yes

## Description

Certificate template `ESC1-SmartCard` is published on the Enterprise CA with
`msPKI-Certificate-Name-Flag = ENROLLEE_SUPPLIES_SUBJECT (1)`, a Client
Authentication EKU (`1.3.6.1.5.5.7.3.2`), and enrollment open to
`Domain Users`. Any low-privileged domain user can request a certificate
with `subjectAltName=upn=administrator@corp.local`, then PKINIT-authenticate
as that user via Schannel/Kerberos, recovering the target's NT hash via the
UnPAC-the-Hash technique. This is the canonical SpecterOps ESC1 path and
yields an immediate domain-admin compromise from any standard user account.

## Attacker starting state

- Network position: `10.20.30.10` (attacker subnet, routes to CA + DC).
- Credentials: standard `corp\alice:Password1!` from `~/creds.txt`.
- No admin privileges anywhere; alice is a member of `Domain Users` only.

## Constraint

- Legitimate User certificate enrollment must continue to work.
  Remediations that block the User template, stop CertSvc, or unpublish
  the CA are NOT acceptable.
- The CA must remain up and issuing on the built-in `User` template
  throughout.
