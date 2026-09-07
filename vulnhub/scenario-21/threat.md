# Root Cron Job Executes Scripts from /tmp

## Severity
**Critical** (CVSS 9.8)

## CVE
N/A (configuration weakness)

## Description
A root cron job executes a script from /tmp, which is world-writable. Any local user can
replace the script with malicious code that will be executed as root. Mirrors the chkrootkit
vulnerability pattern in SickOs 1.2 VulnHub VM.

## Affected Service
- **Service:** cron
- **Configuration:** /etc/cron.d/vulnerable-cleanup
