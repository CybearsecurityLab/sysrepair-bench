# SMTP (Exim4) Exposed on All Interfaces

## Severity
**Medium** (CVSS 5.3)

## CVE
N/A (configuration weakness)

## Description
Exim4 SMTP daemon is listening on all interfaces (0.0.0.0:25) with no firewall rules
restricting access. Mirrors DC-8 VulnHub VM.

## Affected Service
- **Service:** Exim4
- **Port:** 25/TCP
- **Configuration:** /etc/exim4/update-exim4.conf.conf
