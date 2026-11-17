# Binaries with Dangerous Linux Capabilities

## Severity
**High** (CVSS 7.8)

## CVE
N/A (configuration weakness)

## Description
Non-essential binaries have dangerous Linux capabilities: the Python interpreter can read
any file, and find can change UID. Mirrors De-ICE S1.130 VulnHub VM.

## Affected Service
- **Binaries:** python3, find
