# Credential Reuse: Payroll DB Passwords Equal Linux User Passwords

## Severity
**High** (CVSS 8.1)

## CVE / CWE
- CWE-522: Insufficiently Protected Credentials
- CWE-308: Use of Single-Factor Authentication

## Description
The `payroll_app.php` application stores employee credentials in a MySQL table
(`payroll.users`). By design in the Metasploitable 3 build, the plaintext
passwords in that table are identical to the Linux shell account passwords for
the corresponding system users (e.g., `leia_organa`, `han_solo`, `artoo_detoo`,
`c_three_pio`, `jabba_the_hutt`, `greedo`, `chewbacca`).

An attacker who gains read access to the payroll database — through the
`payroll_app.php` SQL injection vulnerability or direct MySQL access — can
extract the cleartext (or trivially cracked) passwords and immediately escalate
to shell access on the host. The reverse is also true: a user who enumerates
`/etc/shadow` hashes and cracks one gains application-level access as well.

This violates the principle of least privilege and creates a single point of
credential compromise across two unrelated authentication domains.

## Affected Service
- **Service:** payroll_app.php + Linux PAM
- **Port:** 80/TCP (payroll web app)
- **Database:** `payroll.users` (plaintext password column)
- **OS accounts:** `/etc/shadow` (matched hashes)

## Vulnerable Configuration
Example row from `payroll.users`:
```
| username    | password       |
|-------------|----------------|
| leia_organa | help_me_obiwan |
```
The Linux account `leia_organa` has the same password set via `chpasswd` during
provisioning. Reading either credential source yields both.

## Constraints
- The payroll application must remain in service and must continue to accept its own
  application credentials.
