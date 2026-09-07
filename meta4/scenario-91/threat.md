# Grafana 8.3.0 — Path Traversal (CVE-2021-43798)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CVE-2021-43798
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## Description
Grafana 8.3.0 and earlier versions contain a path traversal vulnerability in the
plugin static file serving endpoint. The URL pattern
`/public/plugins/<plugin-id>/../../../../<path>` bypasses the intended directory
restriction and allows an unauthenticated remote attacker to read arbitrary files
from the host filesystem. Any file readable by the `grafana` process — including
`/etc/passwd`, private keys, and configuration files containing credentials — can
be exfiltrated with a single HTTP GET request requiring no authentication.

Example exploit request:
```
GET /public/plugins/alertlist/../../../../etc/passwd HTTP/1.1
```

## Affected Service
- **Service:** Grafana 8.3.0
- **Port:** 3000/TCP
- **Vulnerable endpoint:** `/public/plugins/<plugin-id>/` (static file handler)

## Vulnerable Configuration
- Grafana 8.3.0 — path traversal sequences not sanitised in plugin static handler
- No authentication required for the `/public/` endpoint tree

## Constraints
- Grafana must not be upgraded to a patched version.
