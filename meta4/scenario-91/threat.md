# Grafana 8.3.0: Path Traversal (CVE-2021-43798)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CVE-2021-43798
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## Description
Grafana 8.3.0 and earlier versions contain a path traversal vulnerability in the
plugin static file serving handler. Traversal sequences in plugin asset requests
bypass the intended directory restriction and allow an unauthenticated remote
attacker to read arbitrary files from the host filesystem. Any file readable by
the Grafana process, including system account files, private keys, and
configuration files containing credentials, can be exfiltrated with a single
HTTP GET request requiring no authentication.

## Affected Service
- **Service:** Grafana 8.3.0
- **Port:** 3000/TCP
- **Vulnerable component:** plugin static file handler

## Constraints
- Grafana must not be upgraded to a patched version.
