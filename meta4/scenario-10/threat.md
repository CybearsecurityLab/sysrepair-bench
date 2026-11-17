# Tomcat Case-Insensitive JSP Upload Race (CVE-2024-50379)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2024-50379
- CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition

## Description
Tomcat 9.0.0.M1 to 9.0.97, 10.1.0-M1 to 10.1.33, and 11.0.0-M1 to 11.0.1
contain a TOCTOU race in the default servlet when all of the following are
true:

1. The default servlet has write access enabled.
2. The webapp directory resides on a case-insensitive filesystem (common
   on Windows and macOS, and on some Samba/overlay mounts on Linux).
3. An attacker can issue a PUT followed by a GET with case-varied paths.

Under those conditions the JSP filename check can be bypassed: a file
uploaded with a case-varied JSP extension is served and compiled as a JSP,
yielding arbitrary JSP execution as the Tomcat user.

## Affected Service
- **Service:** Apache Tomcat 11.0.1
- **Port:** 8080/TCP
