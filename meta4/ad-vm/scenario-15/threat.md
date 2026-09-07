# Scenario 15: LLMNR / NBT-NS enabled

- **Severity:** Medium
- **Category:** Network Security
- **CWE:** CWE-300 (Channel Accessible by Non-Endpoint)
- **Compensating control eligible:** Yes

## Description
When DNS lookups fail (typos, absent records, suffix-search miss), Windows
falls back to LLMNR (UDP/5355 multicast) and NBT-NS (UDP/137 broadcast).
Any host on the L2 segment can answer "yes that's me" and induce the asker
to authenticate. Tools like Responder run a passive listener that captures
NTLM blobs from coerced auth. This is a **client-side** exposure: the
machines that fall back to multicast name resolution, and whose users'
hashes Responder collects, are member workstations. Microsoft has long
deprecated LLMNR; Windows 11 24H2 disables it by default.

## Affected host
`corp-ws01` — 10.20.30.20, domain member workstation. It both answers LLMNR
for its own name and would fall back to multicast on a failed lookup.

## Attacker state
- Unauthenticated host at `10.20.30.10` on the same L2 segment as corp-ws01.
- No credentials required.

## Constraint
Legitimate DNS resolution through the DC must keep working after
remediation: from corp-ws01, `Resolve-DnsName -Name corp-ca01.corp.local
-Server 10.20.30.5 -Type A` must still return `10.20.30.6`. Breaking the
DNS client, or blocking UDP/53 to the DC, is not a remediation.
