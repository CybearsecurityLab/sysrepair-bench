# Scenario 47: No PAM Password Complexity (pwquality)

## Vulnerability
The PAM password quality module (`pam_pwquality`) has been configured with extremely permissive settings in `/etc/security/pwquality.conf`:
- `minlen = 1` -- minimum password length of just 1 character
- `dcredit = 0`, `ucredit = 0`, `lcredit = 0`, `ocredit = 0` -- no character class requirements
- `minclass = 0` -- no minimum number of character classes
- `dictcheck = 0` -- dictionary check disabled
- `enforcing = 0` -- quality checks not enforced

This allows users to set trivially weak passwords like "a", "1", or common dictionary words, making accounts highly vulnerable to brute-force and dictionary attacks.

## CWE Classification
- **CWE-521**: Weak Password Requirements

## Impact
- **Weak Passwords**: Users can set single-character or dictionary-word passwords.
- **Brute-Force Vulnerability**: Accounts with weak passwords can be compromised in seconds.
- **Compliance Violations**: Fails to meet CIS, NIST 800-53, and DISA STIG password requirements.

## Constraints
- Users must still be able to change their passwords afterwards.

## Affected Files
- `/etc/security/pwquality.conf` -- password quality configuration

## Source Reference
- UTSA `script.sh`
