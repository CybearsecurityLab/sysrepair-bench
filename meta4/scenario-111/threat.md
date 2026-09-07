# Memcached 1.6 — UDP Amplification (CVE-2018-1000115)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CVE-2018-1000115
- CWE-406: Insufficient Control of Network Message Volume (Network Amplification)

## Description
Memcached's UDP interface (port 11211) allows unauthenticated clients to send
small requests that return disproportionately large responses. This property
was exploited in the largest DDoS attack recorded at the time (1.35 Tbps,
GitHub, February 2018). An attacker sends a spoofed UDP `stats` or `get`
request of ~15 bytes; Memcached reflects a response of up to 750 KB,
achieving an amplification factor of approximately **50,000×**.

Because Memcached has no authentication on UDP, any publicly reachable instance
can be weaponised as a reflector/amplifier without any prior access. The
attacker only needs to send packets with a spoofed source IP equal to the
victim's address.

## Affected Service
- **Service:** Memcached 1.6.x (and all prior versions)
- **Port:** 11211/UDP
- **Vulnerable configuration:** default startup without `-U 0`

## Attack Scenario
1. Attacker sends a 15-byte spoofed UDP `stats` packet to Memcached on 11211.
2. Memcached replies with a ~750 KB response to the spoofed victim IP.
3. With thousands of open Memcached nodes, the victim receives multi-Tbps
   traffic — saturating uplinks and causing service outages.
