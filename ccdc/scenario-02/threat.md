# Scenario 02: SSH Allows Empty Passwords

## Vulnerability

The SSH daemon is configured with `PermitEmptyPasswords yes`, allowing users
with empty (blank) passwords to authenticate over SSH. Combined with user
accounts that have no password set, this allows unauthenticated remote access
to the system.

## CWE Classification

### CWE-258: Empty Password in Configuration File

The SSH configuration explicitly permits authentication with empty passwords,
which is functionally equivalent to no authentication at all for affected
accounts. Any user account with a blank password becomes remotely accessible
without credentials.

## Affected Configuration

- **File**: `/etc/ssh/sshd_config`
- **Setting**: `PermitEmptyPasswords yes`
- **Service**: OpenSSH Server (sshd)
- **Affected User**: `emptyuser` (has empty password)

## Constraints

- Normal user SSH access with real passwords must remain functional.

## References

- TAMU ssh.sh
- UTSA script.sh
- CIS Benchmark for Ubuntu - 5.2.11
