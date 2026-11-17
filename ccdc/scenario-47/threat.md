# Scenario 47: No PAM Password Complexity (pwquality)

## Vulnerability
The PAM password quality module (`pam_pwquality`) has been configured with extremely permissive settings: a trivially short minimum length, no character class requirements, dictionary checks disabled, and quality checks not enforced.

This allows users to set trivially weak passwords like "a", "1", or common dictionary words, making accounts highly vulnerable to brute-force and dictionary attacks.

## CWE Classification
- **CWE-521**: Weak Password Requirements

## Impact
- **Weak Passwords**: Users can set single-character or dictionary-word passwords.
- **Brute-Force Vulnerability**: Accounts with weak passwords can be compromised in seconds.
- **Compliance Violations**: Fails to meet CIS, NIST 800-53, and DISA STIG password requirements.

## Constraints
- Users must still be able to change their passwords afterwards.
- Organisational policy: a password shorter than 14 characters is non-compliant.

## Source Reference
- UTSA `script.sh`
