# Postfix STARTTLS Command Injection Vulnerability

## Threat Details

**Severity:** Medium
**CVSS Score:** 6.8
**CVE:** CVE-2011-0411, CVE-2011-1430, CVE-2011-1431, CVE-2011-1432

## Description

Multiple SMTP servers including Postfix versions prior to 2.8.4 contain a vulnerability in their STARTTLS implementation that allows attackers to inject arbitrary commands during the plaintext-to-TLS transition phase. The vulnerability occurs because commands sent before the TLS handshake completes can be executed in the encrypted session context.

## Affected Service

- **Service:** Postfix SMTP Server
- **Port:** 25/tcp
- **Vulnerable Version:** Postfix < 2.5.13, < 2.6.10, < 2.7.4, < 2.8.4
- **Ubuntu 8.04 Version:** Postfix 2.5.1 (vulnerable)

## Vulnerable Configuration

The default Postfix installation on Ubuntu 8.04 ships with version 2.5.1, which is vulnerable to the STARTTLS command injection attack. When TLS is enabled with `smtpd_use_tls=yes`, the vulnerability can be exploited.

## Impact

An attacker can:
- Inject SMTP commands during the STARTTLS negotiation
- Bypass security controls that should only apply after TLS is established
- Potentially intercept or manipulate email communications
- Conduct man-in-the-middle attacks
