# Nacos 1.4.0: Auth Bypass via Spoofed Request Header (CVE-2021-29441)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2021-29441
- CWE-290: Authentication Bypass by Spoofing

## Description
Nacos 1.4.0 implements a built-in bypass for requests originating from
other Nacos cluster nodes. The check is performed by inspecting a
client-supplied HTTP header: if it carries the value identifying a cluster
node, the request is treated as an internal, pre-authenticated cluster call
and all authentication enforcement is skipped.

An unauthenticated external attacker can therefore gain full access to
configuration management, user administration, and all other endpoints of
the Nacos API without valid credentials.

## Affected Service
- **Service:** Alibaba Nacos 1.4.0
- **Port:** 8848/TCP

## Constraints
- The affected package must not be upgraded.
