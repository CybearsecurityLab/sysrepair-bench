# Spring Cloud Function SpEL Injection (CVE-2022-22963)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-22963
- CWE-94: Improper Control of Generation of Code (SpEL injection)

## Description
Spring Cloud Function 3.1.6 and 3.2.2 and earlier accept a
`spring.cloud.function.routing-expression` HTTP header and evaluate it as a
SpEL expression without sandboxing, so a crafted header value executes
arbitrary Java code as the application user. The bundled app
exposes two functions (`uppercase`, `reverse`) at `/functionRouter`;
the header is evaluated before the function is dispatched.

## Affected Service
- **Port:** 8080/TCP
- **Vulnerable artifact:** `/opt/app/app.jar` (Spring Boot fat jar
  containing `spring-cloud-function-web-3.2.2.jar` in `BOOT-INF/lib/`)
- **Vulnerable endpoint:** `POST /functionRouter` with
  `spring.cloud.function.routing-expression` header
