# Scenario 31: No auditd Installed or Configured

## Vulnerability
The system has no audit daemon (auditd) installed or configured. Without system auditing, there is no record of security-relevant events such as unauthorized access attempts, privilege escalation, file modifications, or system call activity. This makes incident detection, forensic analysis, and compliance auditing impossible.

## CWE Classification
- **CWE-778**: Insufficient Logging
- Without auditd, the system cannot log critical security events at the kernel level.

## Affected Components
- `/etc/audit/auditd.conf` - Audit daemon configuration (missing)
- `/etc/audit/rules.d/` - Audit rules directory (missing)
- `auditd` service - Linux Audit Daemon (not installed)

## References
- CIS Ubuntu Linux Benchmark - Section 4.1
- NIST SP 800-53 - AU-2 (Audit Events)
- TAMU configure_auditd.sh
- UTSA script.sh
