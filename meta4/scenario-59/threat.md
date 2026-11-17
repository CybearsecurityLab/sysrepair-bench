# Unbound 1.21: Open Recursive Resolver (DNS Amplification)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-406: Insufficient Control of Network Message Volume (Network Amplification)
- CWE-284: Improper Access Control

## Description
Unbound 1.21 is configured to permit recursive DNS queries from any IPv4 or
IPv6 source address. The server also discloses its software version and
identity to anyone who queries it.

**DNS Amplification attack vector:** UDP-based DNS has no three-way handshake.
An attacker can spoof the source IP of a victim and send a small query
(about 40 bytes) that elicits a large DNSSEC-signed or ANY-type response (up to
4096 bytes with EDNS0). The open resolver forwards this large response to
the spoofed victim IP. With thousands of open resolvers available, attackers
can sustain multi-Gbps floods against a victim using minimal upstream
bandwidth.

The amplification factor for DNS ANY queries can exceed 70x. An Unbound server
reachable on all interfaces without access controls is an immediate candidate
for inclusion in DDoS botnets.

**Version disclosure:** CHAOS class queries return the exact Unbound version
string and server identity. This assists targeted exploitation of known
Unbound vulnerabilities by reducing attacker reconnaissance effort.

## Affected Service
- **Service:** Unbound 1.21
- **Port:** 53/UDP, 53/TCP
