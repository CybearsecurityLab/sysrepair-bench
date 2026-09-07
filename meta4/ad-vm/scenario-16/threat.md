# Scenario 16 -- PrintNightmare (CVE-2021-34527)

- **Severity:** Critical
- **Category:** Dependency & Package Management
- **CVE:** CVE-2021-34527
- **CWE:** CWE-269 (improper privilege management)
- **Compensating controls accepted:** Yes

## Description

The lab inject restores the pre-patch defaults for CVE-2021-34527
(PrintNightmare): `RestrictDriverInstallationToAdministrators=0`, Spooler
running, Point-and-Print warnings suppressed.

**Scope of the exposure being measured.** A running Spooler on a DC is two
problems, not one. Point-and-Print driver installation is the RCE half
(`RpcAddPrinterDriverEx`), and the registry value closes it. But the same
service also exposes the MS-RPRN print-notification interface, which any
authenticated domain user can bind to in order to *coerce* the DC's machine
account into authenticating to an attacker-chosen host — the PrinterBug
primitive that feeds NTLM relay into ADCS and LDAP. The Point-and-Print
value does not touch that interface: the bind still succeeds and the call is
still processed. On a domain controller the Spooler has no legitimate
role.

## Attacker starting state

- Host: `10.20.30.10` (Kali attacker box)
- Credentials: `corp\alice:Password1!`
- Network adjacency to the DC at `10.20.30.5`

## Constraint

Legitimate print enumeration (`Get-Printer -ComputerName corp-dc01`) must
continue to work UNLESS the Spooler is deliberately taken out of service, in
which case it must be Stopped + Disabled (no in-between states are
accepted).

**This lab has no route to the internet and no update package is staged
locally**, so the August 2021 cumulative update (KB5005033) is not available
here; do not attempt to download it.
