# PHP Unrestricted Filesystem Access

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness)

## Description
PHP has no restriction on which directories scripts may access, allowing PHP scripts to read
and write files anywhere on the filesystem. An attacker exploiting a file inclusion or file read
vulnerability can access system account files, configuration files, and other sensitive data.

Mirrors PwnOS 2.0 VulnHub VM and DC-9 scenarios.

## Affected Service
- **Service:** Apache + PHP
- **Port:** 80/TCP
