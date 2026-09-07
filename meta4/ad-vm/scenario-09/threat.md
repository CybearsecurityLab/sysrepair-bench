# Scenario 09 - ADCS ESC3 (Enrollment Agent on-behalf-of)

**Severity:** High
**Category:** Configuration Hardening
**CVE:** n/a (misconfiguration; SpecterOps ESC3 documented technique)
**CWE:** CWE-284 (improper access control)
**Compensating controls accepted:** yes

## Description

ESC3 chains two certificate templates to escalate from any low-privileged
domain user to Administrator. The first template, `ESC3-Agent`, carries the
Certificate Request Agent EKU (`1.3.6.1.4.1.311.20.2.1`) and is enrollable by
`Domain Users`. The second template, `ESC3-User`, issues Client-Authentication
certificates and requires an RA signature from a holder of the
Certificate-Request-Agent EKU (`msPKI-RA-Application-Policies`).

Attack chain: alice enrolls in `ESC3-Agent` and obtains an agent cert. She then
uses that cert to sign a `request on behalf of CORP\Administrator` against
`ESC3-User`. The CA accepts the agent's RA signature and issues a Client-Auth
PFX in Administrator's name. PKINIT-authenticating with the resulting PFX
recovers Administrator's NT hash via UnPAC-the-Hash. End result: full domain
compromise from any standard user account.

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
