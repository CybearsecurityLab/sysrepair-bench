# Git History Credential Leak (misconfig)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-540: Inclusion of Sensitive Information in Source Code

## Description
When a secret is committed to a git repository, it is permanently recorded in
the object database regardless of subsequent commits that remove it. The
"security fix" commit only updates the working tree; it does not rewrite
history. Any user or automated tool with a clone of the repository can
recover the original credential from the commit history.

This affects every copy of the repository: local clones, CI caches, git hosting
mirrors, and backup tarballs. Rotating the exposed credential is mandatory even
after the history is rewritten, because past clones may already hold the secret.

## Affected Service
- **Service:** Application git repository on Debian Bookworm Slim
- **Weakness:** a database credential committed in the repository history
