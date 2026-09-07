# Binaries with Dangerous Linux Capabilities

## Severity
**High** (CVSS 7.8)

## CVE
N/A (configuration weakness)

## Description
Non-essential binaries have dangerous Linux capabilities: python3 has cap_dac_read_search
(read any file), find has cap_setuid (change UID). Mirrors De-ICE S1.130 VulnHub VM.

## Affected Service
- **Binaries:** /usr/bin/python3.7, /usr/bin/find
