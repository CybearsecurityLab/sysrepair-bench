# Scenario 08 - ADCS ESC2 (Any Purpose / no EKU)

**Severity:** Critical
**Category:** Configuration Hardening
**CVE:** n/a (misconfiguration; SpecterOps ESC2 documented technique)
**CWE:** CWE-284 (improper access control)
**Compensating controls accepted:** yes

## Description

Certificate template `ESC2-AnyPurpose` is published on the Enterprise CA with
an empty `pKIExtendedKeyUsage` plus `msPKI-Certificate-Application-Policy =
2.5.29.37.0` (the "Any Purpose" OID). A cert issued from this template carries
no EKU restriction and is therefore valid as a client cert for LDAP Schannel,
RDP, IPSec, code signing, and any other usage the CA's parent allows. The
template additionally has `msPKI-Certificate-Name-Flag =
ENROLLEE_SUPPLIES_SUBJECT (1)` and is enrollable by `Domain Users`, so any
low-privileged user can request a cert with
`subjectAltName=upn=administrator@corp.local` and PKINIT-authenticate as the
target -- recovering the NT hash via UnPAC-the-Hash.

This is distinct from ESC1 in that the issued cert is universally usable
(no Client-Auth EKU restriction). Even if a defender added Schannel-side
EKU filtering, a cert with no EKU constraints bypasses many such checks.
This is the canonical SpecterOps ESC2 path.

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
