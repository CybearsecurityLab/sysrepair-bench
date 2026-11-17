# Apache Tomcat Manager, Default Credentials, Exposed on All Interfaces

## Severity
**Critical** (CVSS 9.8)

## CVE
N/A (configuration weakness; enables arbitrary WAR deploy → RCE via the `manager-script`
role.)

## Description
The Tomcat 8.0.33 instance on this host ships with:

- A default administrative user with a well-known password.
- The manager and admin roles, including `manager-script`, all assigned to that user.
- Address-based access control removed from the Manager application, so it is reachable
  from every source address, not just localhost as the default install would restrict it to.

The `manager-script` role allows authenticated clients to **deploy arbitrary WAR files**.
With known default credentials an attacker gains remote code execution as the Tomcat
service account.

This reproduces the shipped configuration of upstream Metasploitable3.

## Affected Service
- **Service:** Apache Tomcat 8.0.33
- **Port:** 8080/TCP
