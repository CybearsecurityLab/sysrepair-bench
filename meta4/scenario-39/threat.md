# MongoDB 4.4 — No Authentication (misconfig)

## Severity
**High** (CVSS 9.1)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
MongoDB 4.4 ships with authentication disabled by default. When started with
`--bind_ip_all`, the server listens on `0.0.0.0:27017` and accepts connections
from any client on any interface without requiring credentials. An attacker
with network access to the host can connect directly using `mongosh` or the
MongoDB wire protocol and gain full read, write, and administrative control
over every database — including listing, modifying, and dropping collections
and user data.

This is a misconfiguration, not a code vulnerability, but its impact is
equivalent to a critical authentication bypass: there are no credentials to
steal and no exploit to craft. A single command such as:

```
mongosh --quiet --eval "db.adminCommand('listDatabases')"
```

succeeds without any username or password, returning a full inventory of
all hosted databases.

## Affected Service
- **Service:** MongoDB 4.4
- **Port:** 27017/TCP
- **Vulnerable configuration:** `mongod --bind_ip_all` with no `--auth` flag

## Vulnerable Configuration
- MongoDB started without `--auth`, leaving the server in unauthenticated mode
- `--bind_ip_all` (or `--bind_ip 0.0.0.0`) exposes the port to all network interfaces
