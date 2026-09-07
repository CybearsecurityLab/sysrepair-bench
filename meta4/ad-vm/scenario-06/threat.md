# S06 -- DCSync rights granted to non-admin

- **Severity:** Critical
- **Category:** Access Control
- **CVE:** n/a (misconfiguration; the underlying DRS protocol is by design)
- **CWE:** CWE-732 (incorrect permission assignment for critical resource)
- **Compensating controls accepted:** No

## Description

A non-admin user with `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` extended rights on the domain head can issue a DRS replication request and recover every secret in AD, including the krbtgt hash (Golden Ticket key). The two ACEs are the textbook "DCSync" ACL pattern; tooling like `mimikatz lsadump::dcsync` and `impacket-secretsdump -just-dc` use them directly.

## Attacker starting state

10.20.30.10. Domain creds `corp\alice:Password1!`.

## Constraint

DRS replication itself must remain functional for legitimate DCs. `repadmin /showrepl` must continue to enumerate naming contexts.
