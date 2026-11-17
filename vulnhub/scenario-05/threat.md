# Samba Wide Links Symlink Traversal

## Severity
**High** (CVSS 7.5)

## CVE
CVE-2010-0926

## Description
Samba allows following symbolic links outside of shared directories. An authenticated user
can create symbolic links within a share
that point to arbitrary locations on the filesystem, allowing them to read files
outside the shared directory, including sensitive system files.

This is a direct reproduction from the Metasploitable 2 VulnHub VM.

## Affected Service
- **Service:** Samba (smbd)
- **Port:** 139/TCP, 445/TCP
