# SSH Weak MAC Algorithms

## Severity
**Low** (CVSS 2.6)

## CVE
N/A (configuration weakness)

## Description
The OpenSSH server on this system is configured to allow weak Message Authentication Code
(MAC) algorithms. The default configuration of OpenSSH on Ubuntu 8.04 enables MAC algorithms
that are considered cryptographically weak:

- **MD5-based MACs** are vulnerable to collision attacks. While not directly exploitable
  for SSH integrity in most cases, using MD5 violates modern security standards and
  compliance requirements.
- **Truncated SHA-1 MACs** provide only 96 bits of output, reducing the security margin
  below recommended levels.

These weak MACs could theoretically allow an attacker to tamper with SSH traffic without
detection in specific attack scenarios, particularly if combined with other vulnerabilities.

## Affected Service
- **Service:** OpenSSH Server
- **Port:** 22/TCP
