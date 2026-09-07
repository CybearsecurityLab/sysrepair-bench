# Scenario 02 — MachineAccountQuota foothold (NoPac chain)

**Severity:** Critical
**Category:** Access Control
**CVE:** CVE-2021-42278 / CVE-2021-42287 (NoPac chain; this scenario hardens the foothold step)
**CWE:** CWE-269 (improper privilege management)
**Compensating controls accepted:** No

## Description

`ms-DS-MachineAccountQuota=10` is Microsoft's longstanding Windows default.
Any authenticated domain user can create up to 10 computer accounts, which
the NoPac chain renames to a DC's hostname before requesting a service
ticket as DA. The CVEs themselves are patched in the base box; the
residual misconfig is MAQ.

## Attacker starting state

- Network position: `10.20.30.10` (attacker subnet).
- Credentials: domain user `corp\alice:Password1!`.
- No admin privileges on DC.

## Constraint

- Domain-joined computer reads must still work for legitimate DAs.
- `Get-ADComputer corp-ca01 -Server corp-dc01` from a member must still
  succeed after remediation.
- `Domain Admins` must still be able to read and manage computer objects
  afterwards.
- The NoPac patches (KB5008602, KB5008603) are **already present in the base
  image**, and this lab has no route to the internet — there is nothing to
  download and nothing to apply.
