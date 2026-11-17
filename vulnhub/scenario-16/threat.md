# Port Knocking with Insecure Configuration

## Severity
**Medium** (CVSS 5.3)

## CVE
N/A (configuration weakness)

## Description
knockd is configured with a simple, predictable port sequence
that can be easily brute-forced. The timeout is generous and the command provides permanent access.
Mirrors DC-9 VulnHub VM.

## Affected Service
- **Service:** knockd
