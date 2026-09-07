# Port Knocking with Insecure Configuration

## Severity
**Medium** (CVSS 5.3)

## CVE
N/A (configuration weakness)

## Description
knockd is configured with a simple, predictable 3-port sequence (1000, 2000, 3000) that
can be easily brute-forced. The timeout is generous and the command provides permanent access.
Mirrors DC-9 VulnHub VM.

## Affected Service
- **Service:** knockd
- **Configuration:** /etc/knockd.conf
