# HashiCorp Vault 1.13.3: Unencrypted Storage (misconfig)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-312: Cleartext Storage of Sensitive Information

## Description
Vault's file storage backend writes the encrypted keyring and all secret blobs
to its data directory. When no external seal is configured, Vault uses its
built-in Shamir unseal mechanism, which is acceptable, but if the data
directory permissions are too permissive, any local user or container process
can read the raw files. Combined with a leaked unseal key or a misconfigured
auto-unseal that exposes the master key, all secrets stored on disk become
recoverable without going through the Vault API.

Additionally, without an external seal (Transit, AWSKMS, GCP CKMS, etc.),
operators must manually unseal Vault after every restart by providing unseal
key shards, and there is no auditability of when the seal was broken.

## Affected Service
- **Service:** HashiCorp Vault 1.13.3
- **Port:** 8200/TCP
