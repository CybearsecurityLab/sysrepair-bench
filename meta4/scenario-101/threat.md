# Nacos 1.4.0 — Auth Bypass via Spoofed User-Agent (CVE-2021-29441)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2021-29441
- CWE-290: Authentication Bypass by Spoofing

## Description
Nacos 1.4.0 implements a built-in bypass for requests originating from
other Nacos cluster nodes. The check is performed by inspecting the HTTP
`User-Agent` header: if it equals the string `Nacos-Server`, the request
is treated as an internal, pre-authenticated cluster call and all
authentication enforcement is skipped.

An unauthenticated external attacker can exploit this by simply supplying
`User-Agent: Nacos-Server` in any HTTP request to the Nacos API, gaining
full access to configuration management, user administration, and all other
endpoints without valid credentials:

```bash
# PoC: list all users without authentication
curl -s -H 'User-Agent: Nacos-Server' \
    http://<host>:8848/nacos/v1/auth/users?pageNo=1&pageSize=9
```

## Affected Service
- **Service:** Alibaba Nacos 1.4.0
- **Port:** 8848/TCP
- **Vulnerable condition:** direct access to port 8848 without a sanitising proxy

## Constraints
- The affected package must not be upgraded.
