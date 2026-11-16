# InfluxDB 1.7.6 — Empty JWT Shared Secret Auth Bypass (CVE-2019-20933)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2019-20933
- CWE-1188: Initialization with Insecure Default

## Description
InfluxDB 1.7.x supports JWT bearer-token authentication for its HTTP API.
The token is validated against the `shared-secret` value configured in
`influxdb.conf`. CVE-2019-20933 discloses that when `shared-secret` is set
to an empty string (`""`), InfluxDB's JWT validation accepts **any** token
whose HMAC-SHA256 signature was computed with an empty key — including tokens
crafted by an attacker for any username.

Because HMAC with a zero-length key is a valid (if trivially breakable)
operation, an attacker can construct a well-formed JWT claiming to be
the `admin` user, sign it with an empty secret, and present it to the
InfluxDB HTTP API. The server accepts it as legitimate and grants full
administrative access.

## Affected Service
- **Service:** InfluxDB 1.7.6
- **Port:** 8086/TCP (HTTP API)
- **Vulnerable artifact:** `/etc/influxdb/influxdb.conf`

## Vulnerable Configuration
- `[http]` section: `shared-secret = ""` (empty string)
- `auth-enabled = true` (authentication is on but bypassable via JWT)
