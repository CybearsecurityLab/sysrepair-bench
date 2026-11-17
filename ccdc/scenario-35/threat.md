# Scenario 35: NFS Server Unnecessarily Exposed

## Vulnerability

The NFS (Network File System) server is installed and configured with insecure exports. An exported directory is open to all hosts with read-write access and without root privilege squashing, which allows any remote root user to have full root privileges on the exported filesystem. This configuration allows:
- Any host on the network to mount and access the share.
- Remote root users to create SUID binaries, modify files, and escalate privileges.
- Data exfiltration and unauthorized modification.

## CWE Classification

- **CWE-284**: Improper Access Control
- NFS exports are configured without proper host restrictions or privilege squashing.

## Affected Components

- `nfs-kernel-server` service - Running and enabled

## References

- CIS Ubuntu Linux Benchmark - Section 2.2.7
- NIST SP 800-123 (Guide to General Server Security)
- TAMU remove_nfs.sh
