# Squid Proxy with Permissive ACLs

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness)

## Description
Squid proxy permits access from any client, acting as an open proxy. Any user
can route traffic through this proxy for anonymization or to pivot into internal networks.
Mirrors SickOs 1.1 VulnHub VM.

## Affected Service
- **Service:** Squid Proxy
- **Port:** 3128/TCP
