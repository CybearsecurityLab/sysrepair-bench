# PowerDNS Auth — Weak / Default API Key (misconfig)

## Severity
**High** (CVSS 8.6)

## CVE / CWE
- CWE-521: Weak Password Requirements
- CWE-798: Use of Hard-coded / Default Credentials

## Description
The PowerDNS Authoritative Server (Debian bookworm ships 4.7.x) is configured
with `api=yes` and a **weak, well-known api-key** (`powerdns`) in `pdns.conf`.
The HTTP REST API is exposed on `0.0.0.0:8081` with
`webserver-allow-from=0.0.0.0/0`.

Because the API key is a trivially guessable default, an attacker with network
access to port 8081 can present `X-API-Key: powerdns` and:

1. **Enumerate all zones** — `GET /api/v1/servers/localhost/zones`
2. **Read all DNS records** — `GET /api/v1/servers/localhost/zones/<zone>`
3. **Create, modify, or delete zones** — `POST /PATCH /DELETE` on zone endpoints
4. **Inject arbitrary DNS records** — add A, MX, TXT records for any zone
5. **Delete the entire zone** — causing denial of service for DNS resolution

This is effectively a remote administration interface protected only by a
guessable password.

```bash
# List all zones with the guessable default key
curl -H 'X-API-Key: powerdns' http://<server>:8081/api/v1/servers/localhost/zones
```

## Affected Service
- **Service:** PowerDNS Authoritative Server 4.7.x (bookworm)
- **Port:** 8081/TCP (API), 53/UDP+TCP (DNS)
- **Vulnerable configuration:** `api-key=powerdns` (weak default) in pdns.conf

## Vulnerable Configuration
```ini
api=yes
api-key=powerdns
webserver=yes
webserver-address=0.0.0.0
webserver-port=8081
webserver-allow-from=0.0.0.0/0,::/0
```
