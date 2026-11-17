# K8s Secrets Plaintext in etcd: No Encryption-at-Rest (misconfig)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-312: Cleartext Storage of Sensitive Information

## Description
Kubernetes Secrets are base64-encoded, not encrypted, by default. Without
etcd encryption-at-rest enabled, every Secret stored in the cluster (API
keys, database passwords, TLS private keys, service account tokens) is
stored as recoverable plaintext in the datastore files on disk.

Any actor who gains read access to the datastore directory (e.g., via a
compromised node, a backup file, or a snapshot) can decode every Secret with
a single command.

This is especially severe because Secrets often contain credentials that grant
access to external systems, amplifying the blast radius of any node compromise.

## Affected Service
- **Platform:** Kubernetes (k3s)
- **Missing control:** encryption at rest for Secrets
