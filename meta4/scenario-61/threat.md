# Exim 4.96 — SMTP Smuggling (CVE-2023-51766)

## Severity
**Medium** (CVSS 5.3)

## CVE / CWE
- CVE-2023-51766
- CWE-345: Insufficient Verification of Data Authenticity

## Description
Exim 4.96 advertises SMTP extensions CHUNKING (RFC 3030) and PIPELINING
(RFC 2920) to all connecting clients by default. The SMTP smuggling attack
exploits differences in how servers parse the end-of-data sequence when
CHUNKING or PIPELINING is in use: a specially crafted message can cause the
receiving server to interpret embedded bare-LF sequences as message
boundaries, allowing an attacker to inject additional email messages that
appear to pass SPF/DKIM/DMARC validation.

Because the injected messages are delivered as if they were sent by a
legitimate relay, recipients and security filters may treat them as
authenticated mail from a trusted sender.

## Affected Service
- **Service:** Exim 4.96
- **Port:** 25/TCP (SMTP)
- **Vulnerable configuration:** Default Exim config advertises CHUNKING and
  PIPELINING to all hosts

## Vulnerable Configuration
- `chunking_advertise_hosts = *` (Exim default) — advertises CHUNKING to all
- `pipelining_advertise_hosts = *` (Exim default) — advertises PIPELINING to all
