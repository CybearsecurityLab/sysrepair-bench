# HashiCorp Vault 1.13.3 — Dev Mode (misconfig)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CWE-1188: Insecure Default Initialization of Resource

## Description
HashiCorp Vault launched with the `-dev` flag starts in development mode:
the root token is hardcoded to `"root"`, TLS is disabled (plain HTTP), and all
secrets are stored in memory and lost on restart. Because the root token is
publicly known, any process or user that can reach port 8200 has unrestricted
superuser access to every secret, policy, and auth method in the cluster.

An attacker can extract all secrets with a single command:

```
VAULT_ADDR=http://target:8200 vault token lookup root
```

This is a misconfiguration, not a code vulnerability. The `-dev` flag is
explicitly documented as unsafe for production.

## Affected Service
- **Service:** HashiCorp Vault 1.13.3
- **Port:** 8200/TCP
- **Vulnerable configuration:** `vault server -dev`

## Vulnerable Configuration
- Vault started with `-dev` flag
- `VAULT_DEV_ROOT_TOKEN_ID=root` exposes a well-known superuser token
- No TLS — all traffic transmitted in plaintext
- In-memory storage — no data persistence or encryption at rest
