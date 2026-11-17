# Apache Struts 2, Jakarta Multipart Parser OGNL RCE (CVE-2017-5638 / S2-045)

## Severity
**Critical** (CVSS 10.0)

## CVE
- **CVE-2017-5638**, S2-045 Jakarta Multipart parser OGNL injection
- Related: **S2-046** (filename-header vector on the same parser)

## Description
The deployed `struts2-rest-showcase` web application is built on Struts `2.3.20.1`. The
default Jakarta Multipart parser in Struts versions prior to 2.3.32 / 2.5.10.1 evaluates
the `Content-Type` request header as an OGNL expression when the header cannot be
parsed as a valid multipart type. An unauthenticated remote attacker who can reach
port 8080/TCP can execute arbitrary commands in the context of the Tomcat service account.

This is the same finding OpenVAS flags
against the upstream Metasploitable3 Windows build.

## Affected Service
- **Service:** Apache Tomcat 8.0.33 hosting the Struts 2 REST Showcase
- **Port:** 8080/TCP

## Constraints
- This host has no outbound network access, and no fixed Struts distribution is staged on it.
- Tomcat must keep serving on 8080; stopping the container's servlet engine is not an acceptable outcome.
