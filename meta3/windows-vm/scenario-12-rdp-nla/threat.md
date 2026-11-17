# RDP Network Level Authentication (NLA) Disabled, live VM

## Severity
**High** (CVSS 8.1 class, pre-auth RDP surface)

## CVE / Reference
- What made CVE-2019-0708 ("BlueKeep") and CVE-2019-1181/1182 ("DejaBlue") *pre-auth*
  wormable: NLA would have forced authentication before the vulnerable RDP state
  machine was reachable. Disabling NLA re-opens that class of pre-auth surface.

## Description
The RDP listener has Network Level Authentication disabled and a weak security layer,
and `TermService` has been restarted, so TCP/3389 now accepts a plain-RDP X.224
negotiation with no NLA/CredSSP pre-check. The full
RDP protocol state machine is reachable by any unauthenticated attacker.

## Affected Service
- **Service:** `TermService` (Remote Desktop Services), must stay Running, 3389 listening.
- **Port:** 3389/TCP.

## Constraint
- RDP (TCP/3389) must remain reachable after remediation, do NOT fix by disabling
  RDP (`fDenyTSConnections=1`) or stopping `TermService`.
