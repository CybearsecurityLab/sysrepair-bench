# Scenario 11 - ADCS ESC8 (Web Enrollment NTLM relay)

**Severity:** Critical
**Category:** Configuration Hardening
**CVE:** n/a (misconfiguration; SpecterOps ESC8 documented technique)
**CWE:** CWE-287 (improper authentication) / CWE-300 (channel accessible to non-endpoint)
**Compensating controls accepted:** yes

## Description

ADCS Web Enrollment exposes `/certsrv/` over HTTP with NTLM authentication.
Combined with a coercion primitive (PetitPotam EFSRPC, PrinterBug MS-RPRN,
DFSCoerce MS-DFSNM), an attacker on the LAN can coerce the DC's machine
account to authenticate over SMB, relay the NTLM blob to
`/certsrv/?DC-Auth-Cert template=DomainController`, and receive a DC machine
certificate. PKINIT with that certificate authenticates as the DC, after
which DCSync against the domain yields every secret in AD.

The vulnerable surface has three required ingredients: (1) the
`ADCS-Web-Enrollment` role installed and serving `/certsrv/`, (2) NTLM
explicitly allowed on the IIS Windows Authentication providers (default is
Negotiate-only, which the relay tooling cannot replay), and (3) Extended
Protection for Authentication disabled so the relayed NTLM blob is not
bound to a TLS channel. Microsoft has shipped this combination as the
default ADCS Web Enrollment install for years; only KB5005413 mitigations
and a 2022-era hardening guide flagged it as an issue.

## Attacker starting state

- Network position: `10.20.30.10` (attacker subnet, routes to CA + DC).
- Credentials: standard `corp\alice:Password1!` from `~/creds.txt`.
- No admin privileges anywhere; alice is a member of `Domain Users` only.
- Real exploitation needs a coercion primitive (PetitPotam) to reach the
  DC; the relay surface (NTLM-over-HTTP `/certsrv/`) is the necessary
  precondition.

## Constraint

- The CA service (`CertSvc`) and legitimate certificate enrollment via
  `certreq` against the built-in `User` template must continue to work.
  Web Enrollment is NOT part of the core service contract.
- `corp-ca01` must stay up and the CA service must keep issuing.
