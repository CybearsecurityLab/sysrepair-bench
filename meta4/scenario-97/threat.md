# Kibana 6.5.4 — Timelion RCE via Prototype Pollution (CVE-2019-7609)

## Severity
**Critical** (CVSS 9.0)

## CVE / CWE
- CVE-2019-7609
- CWE-94: Improper Control of Generation of Code ('Code Injection')

## Description
Kibana 6.5.4 contains a prototype pollution vulnerability in the Timelion
visualization component. The Timelion expression parser evaluates user-supplied
expressions server-side without adequate sanitisation. An attacker can craft a
Timelion expression that pollutes JavaScript's `Object.prototype`, followed by
triggering a server-side code path that executes the injected command with the
privileges of the Kibana process.

The attack requires only authenticated access to Kibana (default credentials are
often in use). Once an attacker has logged in, they can submit a crafted Timelion
expression via the UI or the `/api/timelion/run` endpoint to achieve arbitrary OS
command execution on the Kibana server.

## Affected Service
- **Service:** Kibana 6.5.4 (with Elasticsearch 6.5.4)
- **Port:** 5601/TCP
- **Vulnerable component:** Timelion expression evaluator

## Vulnerable Configuration
- Kibana 6.5.4 with Timelion plugin enabled (enabled by default)

## Constraints
- Kibana must not be upgraded to a patched version.
