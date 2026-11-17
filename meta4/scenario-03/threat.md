# Log4j 2.16.0 Recursive Lookup DoS (CVE-2021-45105)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CVE-2021-45105
- CWE-674: Uncontrolled Recursion

## Description
Log4j 2.16.0 removed the JNDI lookup but still evaluated recursive
self-referential lookups in Thread Context Map values when a non-default
PatternLayout referenced them. A self-referential lookup value causes
infinite recursion and a StackOverflowError in the logging thread,
terminating request handling: a denial of service.

## Affected Service
- **Port:** 8080/TCP
