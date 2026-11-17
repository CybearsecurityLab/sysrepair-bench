# Rsync Daemon: No Authentication / No ACL (misconfig)

## Severity
**Critical** (CVSS 9.1)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
When the rsync daemon is configured with a module that exposes a filesystem
tree without any user authentication, any client that can reach port 873 can:

- **Read** any file under the exposed tree (including system account files,
  SSH private keys, application secrets).
- **Write** arbitrary files anywhere under the exposed tree (for example, plant
  scheduled jobs or SSH authorized keys).

No credentials, no exploit, no CVE needed: the service simply has no access
control configured.

## Affected Service
- **Service:** rsync daemon (any version)
- **Port:** 873/TCP
