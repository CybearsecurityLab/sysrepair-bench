# Postfix SMTP VRFY/EXPN Enabled

## Severity
**Medium** | CVSS 5.0

## CVE
N/A (configuration weakness)

## Description
The Postfix SMTP server is configured with the VRFY (Verify) and EXPN (Expand) commands enabled. The VRFY command allows a remote user to verify whether a particular email address or username exists on the system, while EXPN can expand mailing list addresses to reveal all member addresses. An attacker can use these commands to enumerate valid usernames and email addresses on the system, which facilitates brute-force attacks, social engineering, and targeted phishing campaigns.

Postfix allows the VRFY command by default. While Postfix does not support EXPN by default, the enabled VRFY command alone provides sufficient information for user enumeration. The responses differ between valid and invalid users, allowing automated enumeration tools to quickly build a list of valid accounts.

## Affected Service
- **Service:** Postfix SMTP Server
- **Port:** 25/tcp
- **Protocol:** SMTP
