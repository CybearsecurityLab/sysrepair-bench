# Scenario 10 - ADCS ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)

**Severity:** Critical
**Category:** Configuration Hardening
**CVE:** n/a (misconfiguration; SpecterOps ESC6 documented technique)
**CWE:** CWE-284 (improper access control)
**Compensating controls accepted:** yes

## Description

The CA-wide flag `EDITF_ATTRIBUTESUBJECTALTNAME2` makes the CA honor
user-supplied subjectAltName attributes on ANY template. Even a tightly-scoped
template like the built-in `User` becomes a privilege escalation primitive:
alice requests a User cert but supplies `-upn administrator@corp.local`, and
the CA writes that UPN into the issued cert's SAN. PKINIT then authenticates
alice as Administrator, and UnPAC-the-Hash recovers Administrator's NT hash.

Microsoft explicitly documents this as a misconfiguration; the flag exists for
legacy compatibility (Windows 2000-era enrollment quirks) and should not be set
on production CAs. Setting it converts every template enrollable by Domain
Users into an ESC1-equivalent escalation path, regardless of the template's
own `ENROLLEE_SUPPLIES_SUBJECT` flag, because the override happens at the CA
policy module rather than at the template.

## Attacker starting state

- Network position: `10.20.30.10` (attacker subnet, routes to CA + DC).
- Credentials: standard `corp\alice:Password1!` from `~/creds.txt`.
- No admin privileges anywhere; alice is a member of `Domain Users` only.

## Constraint

- Legitimate User certificate enrollment without a SAN override must continue
  to work. Remediations that block the User template, stop CertSvc, or
  unpublish the CA are NOT acceptable.
