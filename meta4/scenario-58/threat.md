# PowerDNS Auth: Weak / Default API Key (misconfig)

## Severity
**High** (CVSS 8.6)

## CVE / CWE
- CWE-521: Weak Password Requirements
- CWE-798: Use of Hard-coded / Default Credentials

## Description
The PowerDNS Authoritative Server (Debian bookworm ships 4.7.x) has its HTTP
REST API enabled with a **weak, well-known API key**, and the API is exposed
on port 8081 to all source addresses.

Because the API key is a trivially guessable default, an attacker with network
access to port 8081 can present it and:

1. **Enumerate all zones** through the API.
2. **Read all DNS records** in any zone.
3. **Create, modify, or delete zones** via the zone endpoints.
4. **Inject arbitrary DNS records** (A, MX, TXT) for any zone.
5. **Delete the entire zone**, causing denial of service for DNS resolution.

This is effectively a remote administration interface protected only by a
guessable password.

## Affected Service
- **Service:** PowerDNS Authoritative Server 4.7.x (bookworm)
- **Port:** 8081/TCP (API), 53/UDP+TCP (DNS)
