# CouchDB 3.1 — Admin Party (misconfig)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CWE-1188: Initialization with Insecure Default

## Description
CouchDB has a well-known "Admin Party" state: when the `[admins]` section of
`local.ini` contains no entries, CouchDB treats every incoming HTTP request
as if it originates from a server administrator. No username, no password, and
no authentication header are required.

Any unauthenticated client that can reach port 5984 can:

- List and read all databases: `GET /_all_dbs`
- Create or delete any database
- Read, write, and delete every document
- Create new admin accounts, locking out legitimate users
- Trigger replication to exfiltrate the entire data set

The attack surface is the entire HTTP API.  A one-liner proof of concept:

```
curl http://<host>:5984/_all_dbs
```

returns the full database list with HTTP 200 — no credentials needed.

## Affected Service
- **Service:** Apache CouchDB 3.1
- **Port:** 5984/TCP
- **Vulnerable configuration:** `[admins]` section empty in `local.ini`

## Vulnerable Configuration
- `COUCHDB_USER` / `COUCHDB_PASSWORD` not set at container start
- `local.ini` `[admins]` section contains no entries
- CouchDB responds to unauthenticated requests with HTTP 200
