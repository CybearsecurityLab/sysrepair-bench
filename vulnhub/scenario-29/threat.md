# Custom Service Bound to All Interfaces

## Severity
**Medium** (CVSS 5.3)

## CVE
N/A (configuration weakness)

## Description
A custom service is bound to 0.0.0.0:8888 instead of localhost, exposing it to external
networks. Mirrors De-ICE S1.120 VulnHub VM.

## Affected Service
- **Binary:** /usr/local/bin/custom-service.sh
- **Port:** 8888/TCP
