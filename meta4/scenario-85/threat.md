# HashiCorp Vault 1.13.3: Dev Mode (misconfig)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CWE-1188: Insecure Default Initialization of Resource

## Description
HashiCorp Vault launched in development mode starts with a hardcoded, publicly
known root token, TLS disabled (plain HTTP), and all secrets stored in memory
and lost on restart. Because the root token is publicly known, any process or
user that can reach port 8200 has unrestricted superuser access to every
secret, policy, and auth method in the cluster.

This is a misconfiguration, not a code vulnerability. Development mode is
explicitly documented as unsafe for production.

## Affected Service
- **Service:** HashiCorp Vault 1.13.3
- **Port:** 8200/TCP
