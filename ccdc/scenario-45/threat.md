# Scenario 45: Root Account Unlocked with Weak Password

## Vulnerability
The root account is unlocked and has been set with a trivially weak password (`root123`). An unlocked root account with a weak password is vulnerable to brute-force attacks, especially via services like SSH.

## CWE Classification
- **CWE-521**: Weak Password Requirements

## Impact
- **Brute-Force Attacks**: The weak password `root123` can be cracked in seconds by any password-guessing tool.
- **Direct Root Login**: Attackers can log in directly as root via console, SSH, or `su`, bypassing sudo audit trails.
- **Complete System Compromise**: Root access grants unrestricted control over the entire system.

## Constraints
- Legitimate administrative access through `sudo` or other approved mechanisms must keep working.
- The system must remain functional afterwards.

## Affected Files
- `/etc/shadow` -- root password hash and account status
- `/etc/passwd` -- root account configuration

## Source Reference
- TAMU `passwords.sh`
- UTSA `script.sh`
