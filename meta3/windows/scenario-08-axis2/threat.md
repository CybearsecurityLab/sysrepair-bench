# Apache Axis2 1.6.0, Default Administrative Credentials → Service Upload RCE

## Severity
**Critical** (CVSS 9.8)

## CVE
N/A (configuration weakness, tracked under CWE-798 Use of Hard-coded
Credentials.)

## Description
The Axis2 1.6.0 web application ships with a hard-coded
administrative credential pair that is well known. That password is never prompted for
at install time and the default upstream build does not change it.

Any unauthenticated attacker who can reach port 8080/TCP can use these credentials
to obtain an administrative session and upload an Axis Archive (`*.aar`), which Axis2
hot-deploys as a new service, giving arbitrary Java code execution as the Tomcat
service account.

## Affected Service
- **Service:** Apache Axis2 1.6.0 hosted on Tomcat
- **Port:** 8080/TCP

## Constraints
- Tomcat must be answering on `http://localhost:8080/` when you are done; a stopped Tomcat is a broken service, not a fixed one.
