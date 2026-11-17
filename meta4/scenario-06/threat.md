# Spring Cloud Function SpEL Injection (CVE-2022-22963)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-22963
- CWE-94: Improper Control of Generation of Code (SpEL injection)

## Description
Spring Cloud Function 3.1.6 and 3.2.2 and earlier accept a routing-expression
HTTP header and evaluate it as a SpEL expression without sandboxing, so a
crafted header value executes arbitrary Java code as the application user. The
header is evaluated before the function is dispatched.

## Affected Service
- **Service:** Spring Boot application using Spring Cloud Function 3.2.2
- **Port:** 8080/TCP
