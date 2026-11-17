# OpenSSH regreSSHion (CVE-2024-6387)

## Severity
**High** (CVSS 8.1)

## CVE / CWE
- CVE-2024-6387
- CWE-364: Signal Handler Race Condition

## Description
OpenSSH 8.5p1 through 9.7p1 (and 4.4p1 in some reintroduced configs) have
a signal-handler race in sshd. If a client fails to authenticate within the
login grace time, sshd's SIGALRM handler calls async-unsafe functions
(syslog), causing heap corruption that is exploitable for unauthenticated
remote code execution as root on glibc Linux systems.

The Debian bookworm openssh-server 9.2p1 package is affected.

## Affected Service
- **Service:** OpenSSH sshd
- **Port:** 22/TCP
