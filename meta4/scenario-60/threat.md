# Postfix 3.7 — SMTP Smuggling (CVE-2023-51764)

## Severity
**Medium** (CVSS 5.3)

## CVE / CWE
- CVE-2023-51764
- CWE-345: Insufficient Verification of Data Authenticity

## Description
Postfix 3.7 (and earlier) accepts bare line feeds (LF, `\n`) as line
terminators inside the SMTP DATA phase. The SMTP specification (RFC 5321)
mandates CR+LF (`\r\n`) as the sole valid line terminator. When Postfix
relays mail through intermediaries that are strict about line endings, an
attacker can craft a message body containing bare LF sequences that the
downstream server interprets as the end of one message and the start of a
new, smuggled message — effectively bypassing SPF, DKIM, and DMARC
authentication checks on the injected mail.

This allows an attacker who can send mail through a permissive relay to
inject arbitrary email messages into the delivery queue as if they
originated from a trusted sender, without possessing that sender's signing
keys or IP address.

## Affected Service
- **Service:** Postfix 3.7
- **Port:** 25/TCP (SMTP)
- **Vulnerable configuration:** Default `main.cf` — `smtpd_forbid_bare_newline` not set

## Vulnerable Configuration
- Postfix installed with default `main.cf` does not set `smtpd_forbid_bare_newline`
- The default value (`no`) accepts bare LF characters in the DATA stream
