# S12 - LDAP signing not required (NTLM relay surface)

- **Severity:** High
- **Category:** Compensating Controls
- **CVE:** n/a
- **CWE:** CWE-287 / CWE-300
- **Comp-ctrl:** Yes

## Description
When LDAP signing is not required (`LDAPServerIntegrity=1`), the DC accepts
unsigned simple binds and unsigned SASL binds. NTLM blobs captured via
PetitPotam, PrinterBug, or LLMNR poisoning can be replayed straight to the
DC's LDAP listener with no integrity check. Combined with `ldap-relay-scan`,
attackers add their own user to a privileged group or write
`msDS-AllowedToActOnBehalfOfOtherIdentity` for resource-based constrained
delegation takeover.

## Attacker state
- Source: 10.20.30.10 (attacker host)
- Credential: `corp\alice:Password1!`

## Constraint
Legitimate signed LDAP binds must keep working.
