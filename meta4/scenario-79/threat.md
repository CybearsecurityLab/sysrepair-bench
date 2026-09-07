# K8s Secrets Plaintext in etcd — No Encryption-at-Rest (misconfig)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-312: Cleartext Storage of Sensitive Information

## Description
Kubernetes Secrets are base64-encoded, not encrypted, by default. Without
etcd encryption-at-rest enabled, every Secret stored in the cluster — API
keys, database passwords, TLS private keys, service account tokens — is
stored as recoverable plaintext in the etcd datastore files on disk.

Any actor who gains read access to the etcd data directory (e.g., via a
compromised node, a backup file, or a snapshot) can decode every Secret with
a single command:

```bash
# On the node with etcd data:
strings /var/lib/rancher/k3s/server/db/current/etcd/member/snap/db \
    | grep -A1 "password"
# Returns the raw plaintext value
```

This is especially severe because Secrets often contain credentials that grant
access to external systems, amplifying the blast radius of any node compromise.

## Affected Service
- **Platform:** Kubernetes (k3s)
- **Storage backend:** k3s embedded SQLite / etcd
- **Missing control:** EncryptionConfiguration with `aescbc` or `secretbox`

## Vulnerable Configuration
- k3s started without `--encryption-provider-config` flag
- No EncryptionConfiguration file at `/etc/rancher/k3s/encryption-config.yaml`
- All Secrets stored as base64 in the datastore with no encryption envelope
