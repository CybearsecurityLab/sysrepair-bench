# Confluence Widget Connector SSTI -> RCE (CVE-2019-3396, simulated)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2019-3396
- CWE-1336: Server-Side Template Injection / CWE-22: Path Traversal

## Description
The Widget Connector macro in Atlassian Confluence Server/Data Center before
6.6.12, 6.12.x < 6.12.3, 6.13.x < 6.13.3 and 6.14.x < 6.14.2 lets an
unauthenticated attacker POST to `/rest/tinymce/1/macro/preview` with a
`_template` parameter that is loaded and evaluated as a server-side Velocity
template. A path-traversal path yields arbitrary file read; an embedded
directive yields remote code execution. It was mass-exploited in 2019 to drop
GandCrab ransomware and cryptominers.

## This scenario is a SIMULATION (and a re-point)
Real Confluence only boots into an un-configured setup wizard inside the
harness, so this scenario runs a faithful **Python/Flask simulation** on port
8090 that reproduces the CVE's actual behaviour: the macro-preview handler
evaluates the attacker-supplied `_template`, so the sim **actually executes the
embedded command / reads the traversed file**. It is a simulation of
CVE-2019-3396, not a real Confluence server.

Note: scenario-113 already simulates CVE-2022-26134 (OGNL-in-URI). To avoid a
duplicate, this scenario targets a **different Confluence CVE, endpoint, and
vulnerability class** (Widget Connector Velocity SSTI / path traversal).

Exploit (unauthenticated):
```
POST /rest/tinymce/1/macro/preview   _template=$exec(id)                 # RCE
POST /rest/tinymce/1/macro/preview   _template=../../../../etc/passwd    # file read
```

## Affected Service
- **Service:** Confluence Server (simulated with Python/Flask)
- **Port:** 8090/TCP
