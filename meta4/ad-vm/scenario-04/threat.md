# Scenario 04 -- AS-REP Roasting (dave: DONT_REQ_PREAUTH + weak pwd)

- **Severity:** High
- **Category:** Compensating Controls
- **CVE:** n/a
- **CWE:** CWE-287 (Improper Authentication) / CWE-326 (Inadequate Encryption Strength)
- **Compensating control:** Yes

## Description

The Active Directory user-account-control flag `UF_DONT_REQUIRE_PREAUTH`
(surfaced in PowerShell as `DoesNotRequirePreAuth=True`) disables Kerberos
pre-authentication for the account. With pre-auth disabled the KDC will
respond to an unauthenticated AS-REQ with an AS-REP whose enc-part is
encrypted under the user's long-term key (RC4-HMAC by default). An
attacker on the network can request that AS-REP without any credentials,
take it offline, and brute-force the user's password against a wordlist.
When the account also has a weak/dictionary password (here `Winter24`,
6 letters + 2 digits, top of every seasonal list), the crack is
sub-second on commodity hardware.

## Attacker state

- Network position: 10.20.30.10 (attacker VM), no AD credentials.
- Tooling: `impacket-GetNPUsers` to dump AS-REPs, `hashcat -m 18200` to
  crack them.
- AS-REP roasting is fully pre-auth: no creds, no SMB session, no LDAP
  bind required -- only routable access to TCP/UDP 88 on the DC.

## Constraint

Legitimate password-based Kerberos authentication for `dave` must keep
working. The account must not be disabled or locked out.

## Why "Compensating Controls"

There is nothing to patch here -- AS-REP roasting is a feature of the
Kerberos protocol exposed by an account-level UAC bit. This is the
defining shape of the Compensating Controls category.
