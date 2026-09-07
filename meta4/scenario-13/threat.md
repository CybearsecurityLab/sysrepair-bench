# Confluence Broken Access Control — Admin Creation (CVE-2023-22515, simulated)

## Severity
**Critical** (CVSS 10.0)

## CVE / CWE
- CVE-2023-22515
- CWE-284: Improper Access Control

## Description
Atlassian Confluence Data Center/Server 8.0.0–8.3.2, 8.4.0–8.4.2 and
8.5.0–8.5.1 can be forced back into their initial-setup state by an
unauthenticated request to `/setup/setupadministrator.action?trigger=true`.
Once the "setup complete" flag is cleared, an attacker POSTs to the same
endpoint to create a brand-new administrator account, bypassing all
authentication. It was exploited as a 0-day in 2023.

## This scenario is a SIMULATION
The real Confluence Data Center image only boots into an un-configured setup
wizard inside the harness and never reaches a state where this CVE is testable.
This scenario therefore runs a faithful **Python/Flask simulation** on port
8090 that reproduces the CVE's actual behaviour: the setup endpoint honours
unauthenticated setup-reopen and admin-creation requests and **mutates real
server state** (a new administrator is added to the instance's admin set). It
is a simulation of CVE-2023-22515, not a real Confluence server.

Exploit (unauthenticated):
```
GET  /setup/setupadministrator.action?trigger=true
POST /setup/setupadministrator.action   (username=attacker&password=...)
```
The new admin then appears in `/rest/api/admins`.

## Affected Service
- **Service:** Confluence Server 8.3.2 (simulated with Python/Flask)
- **Port:** 8090/TCP
