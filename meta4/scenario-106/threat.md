# Apache APISIX Default Admin Token (CVE-2020-13945)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2020-13945
- CWE-1188: Insecure Default Initialization of Resource

## Description
Apache APISIX ships with a hardcoded default admin API key. The admin REST API
accepts this key out of the box. Any client that knows the published default,
which is readily available in public documentation, GitHub, and exploit
databases, can authenticate to the admin API and perform any administrative
action, including uploading arbitrary Lua scripts through route objects.

Because Lua scripts execute server-side with the privileges of the APISIX
process, an attacker can achieve full Remote Code Execution.

## Affected Service
- **Service:** Apache APISIX
- **Port:** 9080/TCP (admin API)
- **Vulnerable versions:** APISIX up to 2.0 (with default config)
