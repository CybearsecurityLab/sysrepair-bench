# Scenario 14 -- NTLMv1 downgrade allowed on the DC

- **Severity:** High
- **Category:** Compensating Controls
- **CWE:** CWE-326 / CWE-916 (use of password hash with insufficient computational effort)
- **Comp-ctrl:** Yes

## Description

NTLMv1 challenge-response uses DES with a fixed 8-byte challenge, deriving
three sub-hashes from the user's NT hash. Captured NTLMv1 hashes are
crackable to the underlying NT hash in <24h via the public crack.sh
rainbow tables, after which the attacker has the user's password-equivalent
hash for pass-the-hash, NTLM relay, etc. The exposure is purely
deployment: the protocol is supported for legacy clients and many
enterprises leave `LmCompatibilityLevel` at 2 or 3.

## Attacker state

- Host: 10.20.30.10
- Credentials: `corp\alice:Password1!`

## Constraint

SMB on the DC must keep working for member SYSVOL/Netlogon reads.
