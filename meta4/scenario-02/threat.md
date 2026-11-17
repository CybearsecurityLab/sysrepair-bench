# Log4j 2.15.0 Thread Context Map Bypass (CVE-2021-45046)

## Severity
**Critical** (CVSS 9.0)

## CVE / CWE
- CVE-2021-45046
- CWE-917: Expression Language Injection

## Description
Log4j 2.15.0 was the initial fix for CVE-2021-44228 but its mitigation was
incomplete. When a logging configuration uses a non-default PatternLayout
that references the Thread Context Map or a Thread Context Stack pattern,
attacker-controlled values placed into the context can still include JNDI
lookup expressions and trigger remote code execution in vulnerable JNDI
environments, or cause information disclosure.

The bundled application logs an HTTP-query-derived ThreadContext value and
its logging configuration expands it at layout time, which is exactly the
affected shape.

## Affected Service
- **Port:** 8080/TCP
