# JetBrains TeamCity Auth Bypass -> RCE (CVE-2023-42793, simulated)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2023-42793
- CWE-288: Authentication Bypass Using an Alternate Path

## Description
TeamCity On-Premises before 2023.05.4 exposes a code path allowing an
unauthenticated attacker to mint an administrator-scoped API token:
```
POST /app/rest/users/id:1/tokens/RPC2
```
With that token the attacker creates a new admin, edits build configs, or
injects a build step that runs arbitrary commands. The chain was weaponised in
2023 by APT29.

## This scenario is a SIMULATION
Real TeamCity halts at its first-run screen and 503s every endpoint inside the
harness, so this scenario runs a faithful **Python/Flask simulation** on port
8111 that reproduces the CVE's actual chain: the token endpoint mints a valid
admin-scoped token without authentication, and that token then authorises a
privileged action (creating a new administrator — a **real state change**). It
is a simulation of CVE-2023-42793, not a real TeamCity server.

Exploit (unauthenticated):
```
POST /app/rest/users/id:1/tokens/RPC2        -> {"value":"<admin token>"}
POST /app/rest/users  (Bearer <admin token>) -> creates a new administrator
```

## Affected Service
- **Service:** JetBrains TeamCity On-Premises 2023.05.3 (simulated with Flask)
- **Port:** 8111/TCP
