# Scenario 44: Unauthorized User in Sudo Group

## Vulnerability
A user has been added to the `sudo` group without authorization. According to the organization's policy, only an authorized list of users should have sudo privileges. The unauthorized account can now execute any command as root using `sudo`, which violates the principle of least privilege.

## CWE Classification
- **CWE-269**: Improper Privilege Management

## Impact
- **Unauthorized Privilege Escalation**: The unauthorized user can run any command as root via `sudo`.
- **Policy Violation**: The sudo group membership does not match the authorized list, indicating either a misconfiguration or a deliberate insider threat.
- **Lateral Movement**: A compromised account of this kind would grant an attacker full root access.

## Constraints
- Authorized sudo users listed in `/opt/authorized_sudoers` (e.g., `admin`) must retain their sudo access.

## Source Reference
- TAMU `passwords.sh`
