# Spring4Shell (CVE-2022-22965)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-22965
- CWE-20: Improper Input Validation (data binder)

## Description
Spring Framework 5.3.0 to 5.3.17 and 5.2.0 to 5.2.19 on JDK 9+ allowed the
request data-binder to walk arbitrary property chains on a request-backed
POJO. An attacker can use crafted request parameters to overwrite Tomcat's
access-log valve fields, writing an attacker-controlled JSP file into the
webroot for remote code execution.

Stack requirements, all present in this image:
- Spring Framework 5.3.17 or earlier
- Deployment as a WAR on Tomcat (9.0.60 here)
- JDK 9 or later (here: JDK 11)
- A Spring MVC endpoint that binds a non-basic POJO from the request.

## Affected Service
- **Service:** Apache Tomcat 9.0.60 with Spring 5.3.17 WAR
- **Port:** 8080/TCP
