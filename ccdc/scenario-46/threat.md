# Scenario 46: No Password Aging Policy

## Vulnerability
The system's password aging policy has been configured with insecure values: passwords essentially never expire, can be changed immediately with no minimum age, and users receive no warning before password expiration.

Without proper password aging, compromised credentials can be used indefinitely. The lack of a minimum password age also allows users to cycle through password changes to return to their original password, defeating password history policies.

## CWE Classification
- **CWE-263**: Password Aging with Long Expiration

## Impact
- **Credential Persistence**: Compromised passwords remain valid indefinitely without forced rotation.
- **Password History Bypass**: With no minimum age, users can rapidly change passwords to exhaust the password history and reuse old passwords.
- **Compliance Violations**: Most security frameworks (CIS, NIST, DISA STIG) require password aging policies.

## Constraints
- Existing users must still be able to change their passwords afterwards.
- Organisational policy: a password older than 365 days is non-compliant, a password must stay in place for at least 1 day before it can be changed again, and users must be warned at least 7 days before it expires.

## Source Reference
- TAMU `login_defs.sh`
- UTSA `script.sh`
