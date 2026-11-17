# BIND 9.18: AXFR Zone Transfer Open (misconfig)

## Severity
**Medium** (CVSS 5.3)

## CVE / CWE
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

## Description
BIND 9.18 is configured to allow zone transfers to any client, both globally
and per zone. This permits any host to request a full DNS zone transfer (AXFR)
over TCP port 53.

A zone transfer returns every DNS record in a zone in a single response:
A records, MX records, CNAME records, TXT records, and internal hostnames.
For an attacker performing reconnaissance, this is equivalent to receiving a
complete map of the target's internal network topology (host names, internal
IP addresses, mail servers, load balancers, and application servers) without
any authentication.

## Affected Service
- **Service:** BIND 9.18
- **Port:** 53/TCP
