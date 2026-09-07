# Scenario 17: PetitPotam EFSRPC coerced authentication (CVE-2021-36942 / ADV210003)

- **Severity**: High
- **Category**: Configuration Hardening
- **CVE**: CVE-2021-36942 (PetitPotam) + Microsoft advisory ADV210003
- **CWE**: CWE-918 / CWE-287
- **Compensating controls accepted**: Yes

## Description

The EFS RPC interface (`c681d488-d850-11d0-8c52-00c04fd90f7e`) exposes opnum 0
(`EfsRpcOpenFileRaw`) and a handful of similar calls that take a UNC path
argument. A coerced auth attack reaches one of these opnums with an
attacker-controlled UNC, causing the DC's machine account to authenticate to
the attacker's host.

## Attacker starting state

- 10.20.30.10
- `corp\alice:Password1!`

## Constraint

Local EFS file operations on the DC (`cipher /e`, `cipher /d`) must keep
working. The local EFS code path must not be broken.

**This lab has no route to the internet and no update package is staged
locally**, so the August 2021 cumulative update (KB5005010 / KB5005033) is
not available here; do not attempt to download it.
