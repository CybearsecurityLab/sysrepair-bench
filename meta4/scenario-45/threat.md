# InfluxDB 1.7.6: Empty JWT Shared Secret Auth Bypass (CVE-2019-20933)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2019-20933
- CWE-1188: Initialization with Insecure Default

## Description
InfluxDB 1.7.x supports JWT bearer-token authentication for its HTTP API.
CVE-2019-20933 discloses that when the JWT shared secret is empty, InfluxDB's
JWT validation accepts **any** token whose HMAC-SHA256 signature was computed
with an empty key, including tokens crafted by an attacker for any username.

Because HMAC with a zero-length key is a valid (if trivially breakable)
operation, an attacker can construct a well-formed JWT claiming to be the
admin user, sign it with an empty secret, and present it to the InfluxDB HTTP
API. The server accepts it as legitimate and grants full administrative
access, even though authentication is nominally enabled.

## Affected Service
- **Service:** InfluxDB 1.7.6
- **Port:** 8086/TCP (HTTP API)
