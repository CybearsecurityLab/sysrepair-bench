# Scenario 01: SSH Permits Root Login

## Vulnerability

The SSH daemon allows direct remote root login over SSH. This gives attackers
who obtain or brute-force the root password full, unrestricted access to the
system without any audit trail distinguishing which administrator performed an
action.

## CWE Classification

**CWE-250: Execution with Unnecessary Privileges**

Allowing direct root login via SSH grants the highest level of system privileges
to any authenticated session. Normal administrative workflows should use
unprivileged accounts with `sudo` for privilege escalation, providing
accountability and limiting the blast radius of compromised credentials.

## Affected Service

OpenSSH Server (sshd)

## Constraints

- Normal user SSH access must remain functional.

## References

- TAMU ssh.sh
- UTSA script.sh
- CIS Benchmark for Ubuntu - 5.2.10
