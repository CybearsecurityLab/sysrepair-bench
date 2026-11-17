# Apache Solr 8.11.0: Log4Shell (CVE-2021-44228)

## Severity
**Critical** (CVSS 10.0)

## CVE / CWE
- CVE-2021-44228 (Log4Shell)
- CWE-917: Improper Neutralization of Special Elements used in an Expression Language

## Description
Apache Solr 8.11.0 bundles a version of Log4j 2 that evaluates JNDI lookup
expressions embedded in logged strings (Log4j 2.0-beta9 through 2.14.1). Any
user-controlled input that reaches a logger, such as Solr query parameters or
HTTP headers, can trigger a lookup against an attacker-controlled LDAP or RMI
server, which returns a serialized Java class that Log4j loads and executes.
This gives unauthenticated remote code execution as the Solr process user.

Solr's admin handler logs query parameters at INFO level, so unauthenticated
request parameters reach Log4j.

## Affected Service
- **Service:** Apache Solr 8.11.0
- **Port:** 8983/TCP
