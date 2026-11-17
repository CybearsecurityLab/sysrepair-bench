# Scenario 43: Unauthorized UID 0 User

## Vulnerability
An unauthorized user account has been created with UID 0 (the same UID as root). On Unix/Linux systems, UID 0 grants full superuser privileges regardless of the account name. This means the account has unrestricted root access to the entire system, effectively creating a hidden administrative account that bypasses normal authentication and auditing.

## CWE Classification
- **CWE-269**: Improper Privilege Management

## Impact
- **Hidden Root Access**: The account provides full root privileges while appearing as a normal user in logs.
- **Audit Evasion**: Actions performed by the account may be attributed to root or may not trigger alerts configured for the root account.
- **Persistent Backdoor**: Attackers can maintain root access even if the root password is changed.

## Constraints
- The `root` account must still function correctly afterwards.

## Source Reference
- TAMU `uid_0_users.sh`
- TAMU `gid_0.sh`
