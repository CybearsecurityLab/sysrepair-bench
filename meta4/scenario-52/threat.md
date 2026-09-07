# NATS 2.7.1 — No Authentication / Cross-Tenant Account Switching (CVE-2022-24450)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-24450
- CWE-306: Missing Authentication for Critical Function

## Description
NATS Server 2.7.1 is vulnerable to unauthenticated access and cross-tenant
account switching. When no `authorization` or `accounts` block is present in
`nats-server.conf`, the server accepts connections from any client without
requiring credentials. Additionally, CVE-2022-24450 allows an authenticated
client in one account to switch into a different account by sending a crafted
`CONNECT` message with a spoofed account name, bypassing account isolation
that is the primary multi-tenancy security boundary in NATS.

Combined, these issues mean:
- Any unauthenticated client can connect, publish, and subscribe to all subjects
- A client in a low-privilege account can elevate into a high-privilege account
  and access subjects they should not be able to see
- Sensitive messages (credentials, telemetry, commands) are exposed to all
  connected clients

There is no exploit to craft for the no-auth case — a plain `nats-server`
connection without credentials succeeds immediately:
```
nats pub test "hello" --server nats://<host>:4222
```

## Affected Service
- **Service:** NATS Server 2.7.1
- **Port:** 4222/TCP (client connections), 8222/TCP (HTTP monitoring)
- **Vulnerable configuration:** No `authorization` block in `nats-server.conf`

## Vulnerable Configuration
- `nats-server.conf` contains no `authorization` or `accounts` block
- All subjects are world-readable and world-writable
- Account isolation is absent, enabling cross-tenant switching
