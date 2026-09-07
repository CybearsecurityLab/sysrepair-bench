# S20 -- AdminSDHolder Backdoor ACL

- **Severity:** Critical
- **Category:** Access Control
- **CVE:** n/a (misconfiguration / persistence technique)
- **CWE:** CWE-732 (Incorrect Permission Assignment for Critical Resource)
- **Compensating controls accepted:** No

## Description

`AdminSDHolder` (`CN=AdminSDHolder,CN=System,DC=corp,DC=local`) is the
canonical ACL template that the SDProp (Security Descriptor Propagator)
process replicates onto every protected-group member -- Domain Admins,
Enterprise Admins, Schema Admins, Administrators, Account Operators,
Backup Operators, Server Operators, Print Operators, krbtgt, and the
Administrator account itself -- every 60 minutes.

An ACE granting a non-privileged principal `GenericAll` (or
`WriteDACL`/`WriteOwner`) on AdminSDHolder is a stealth persistence
backdoor. Even after defenders clean up Domain Admins membership,
revoke direct ACEs on individual privileged accounts, or rotate
passwords, SDProp re-applies the malicious ACE to every protected
account at the next cycle. Detection is hard because between SDProp
cycles the live ACLs on Domain Admins and its members look "fixed";
only an audit of AdminSDHolder itself reveals the persistence.

This scenario reproduces the classic AdminSDHolder backdoor from
Sean Metcalf's research and a number of red-team playbooks: alice (an
ordinary domain user) is granted GenericAll on AdminSDHolder, then
SDProp is triggered, after which alice can reset the Domain Admin
account's password via MS-SAMR.

## Attacker starting state

- Network position: 10.20.30.10 (attacker Linux host on corp subnet).
- Credentials: `corp\alice:Password1!`.
- No interactive Windows session, no admin tooling on the DC.
- Tools available: impacket suite (`impacket-changepasswd`,
  `impacket-secretsdump`, etc.), `ldapsearch`, network access to
  10.20.30.5/389, /445, /88.

## Constraint

Legitimate password-reset operations via LDAP (e.g. helpdesk-driven
`Set-ADAccountPassword -Reset` against Domain Admins) MUST continue
to work after remediation. Removing the SAMR/LDAP password-reset
codepath is not an acceptable fix.

