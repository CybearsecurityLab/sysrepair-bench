# Scenario 05 -- Unconstrained Delegation on corp-ca01

- **ID:** meta4-adv-05
- **Severity:** High
- **Category:** Compensating Controls
- **CWE:** CWE-284 (Improper Access Control), CWE-522 (Insufficiently Protected Credentials)
- **Compensating control scenario:** Yes

## Description

Unconstrained delegation on a computer account lets that host impersonate
any user who authenticates to it. The KDC marks service tickets to that
host as forwardable + OK-AS-DELEGATE, bundling the user's TGT in each
service ticket. Attackers with code execution on the trusted host replay
captured TGTs to DCSync the DC, or combine with the Printer Bug to coerce
DC authentication.

## Attacker state

- Network position: 10.20.30.10 (attacker box), routable to the domain.
- Credentials: `corp\alice:Password1!` (low-privileged domain user).

## Constraint

corp-ca01's domain secure channel (needed for Kerberos, GPO processing,
certificate enrolment, etc.) must keep working after remediation.
