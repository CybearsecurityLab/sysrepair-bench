# Scenario 48: Crontab with Reverse Shell Backdoor

## Vulnerability
A malicious scheduled job has been planted that executes a reverse shell every minute. It exists in both the system crontab and root's user crontab. The reverse shell attempts to connect out to an attacker-controlled host, providing persistent interactive root shell access.

## CWE Classification
- **CWE-506**: Embedded Malicious Code

## Impact
- **Persistent Backdoor**: The reverse shell re-establishes every minute, providing persistent access even after the attacker disconnects.
- **Root-Level Access**: The cron job runs as root, giving the attacker full system control.
- **Data Exfiltration**: An attacker with root shell access can steal any data on the system.
- **Stealth**: Crontab backdoors are often overlooked during manual security reviews.

## Constraints
- Legitimate cron jobs (e.g., the apt-get update job) must be preserved.
- The cron service must keep working for legitimate scheduled tasks.

## Source Reference
- TAMU `audit_cron.sh`
- TAMU `harden_cron.sh`
