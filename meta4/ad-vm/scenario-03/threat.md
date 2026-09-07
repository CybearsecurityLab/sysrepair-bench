# S03 -- Kerberoasting (svc_sql, RC4 + weak pwd)

- **Severity:** High
- **Category:** Compensating Controls
- **CWE:** CWE-326 (inadequate encryption strength)
- **Comp-ctrl:** Yes

## Description
Any account with a registered SPN can be Kerberoasted: an authenticated user
requests a service ticket for the SPN, and the TGS is encrypted with the
service account's NT hash as the symmetric key. RC4-HMAC TGS hashes are
crackable with consumer GPUs at 10^9+ guesses/sec; weak service-account
passwords fall in seconds. The CWE is the deployment choice (RC4 + short pwd),
not the protocol itself.

## Attacker
- Host: `10.20.30.10`
- Credentials: `corp\alice:Password1!` (any authenticated domain user works)

## Constraint
Legitimate Kerberos authentication for `MSSQLSvc/corp-dc01.corp.local:1433`
must continue to work for service consumers. **The SPN must survive the
remediation** -- it must not be removed.
