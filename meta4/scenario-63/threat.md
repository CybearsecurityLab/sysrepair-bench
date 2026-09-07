# Roundcube 1.6.3 — SVG-Based Stored XSS (CVE-2023-5631)

## Severity
**Medium** (CVSS 6.1)

## CVE / CWE
- CVE-2023-5631
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

## Description
Roundcube 1.6.3 does not adequately sanitize SVG elements embedded in HTML
email messages. When a victim opens a crafted email containing a malicious SVG
payload, the SVG is rendered inline in the browser within the Roundcube web
interface. SVG supports embedded JavaScript via event handlers and `<script>`
tags, which execute in the context of the Roundcube origin. An attacker who
can send email to a Roundcube user can therefore execute arbitrary JavaScript
in the victim's browser session, enabling session hijacking, credential theft,
or unauthorized email actions.

This vulnerability is stored (persistent) — the payload is saved in the
mail server and fires every time the victim opens or previews the email.

## Affected Service
- **Service:** Roundcube 1.6.3 (Apache)
- **Port:** 80/TCP (HTTP)
- **Vulnerable component:** HTML email renderer — SVG element handling

## Vulnerable Configuration
- Roundcube 1.6.3 with default configuration renders SVG content from HTML
  emails without stripping potentially malicious SVG elements
- No Content-Security-Policy header is set by default

## Constraints
- Roundcube must not be upgraded to a patched version.
