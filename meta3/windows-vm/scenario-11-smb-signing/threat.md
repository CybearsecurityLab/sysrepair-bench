# SMB Signing Not Required (NTLM Relay Surface) — live VM

## Severity
**High** (CVSS 8.1 class)

## CVE / Reference
- CVE-2019-1040, CVE-2019-1166 — NTLM tampering / MIC bypass enabling relay.
- CWE-326 (inadequate encryption strength) / CWE-757 (algorithm downgrade).

## Description
The SMB server has `RequireSecuritySignature = 0` (signing offered but not required)
and `LanmanServer` has been restarted, so a live SMB2 NEGOTIATE against TCP/445 now
returns a SecurityMode **without** the "signing required" bit. Any coerced NTLM
authentication (PetitPotam, PrinterBug, etc.) can be relayed to SMB without a
signing-mismatch rejection, enabling lateral code execution.

## Affected Service
- **Service:** `LanmanServer` — must stay Running, 445 listening.
- **Port:** 445/TCP.
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature`

## Constraint
- TCP/445 must remain reachable for legitimate clients (SYSVOL reads, file shares).
  Do NOT fix by stopping/disabling `LanmanServer`.
