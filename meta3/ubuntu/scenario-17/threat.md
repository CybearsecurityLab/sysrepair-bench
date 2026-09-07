# payroll_app.php SQL Injection

## Severity
**High** (CVSS 8.8) — vulnerability; WAF reduces exploitability to Low

## CVE / CWE
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command
- No public CVE (application-specific, bespoke PHP)

## Category
Compensating Control — `payroll_app.php` is a third-party binary whose source
cannot be modified.

## Description
`payroll_app.php` constructs MySQL queries by directly interpolating POST
parameters without prepared statements or escaping:

```php
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
```

An attacker can submit a tautology or UNION-based payload in the `username`
field to bypass authentication or dump the database:

- Tautology bypass: `username=admin' OR '1'='1`
- UNION dump: `username=' UNION SELECT 1,2,3,table_name FROM information_schema.tables-- -`

Because the PHP source is locked (binary-distributed, vendor-controlled, or
policy-protected), the SQLi cannot be patched in code.

## Affected Service
- **Service:** Apache2 + payroll_app.php
- **Port:** 80/TCP
- **Path:** `/payroll_app.php`

## Constraint
`payroll_app.php` must remain running and must accept legitimate username/password
combinations. The compensating control must not disable or replace the application.
