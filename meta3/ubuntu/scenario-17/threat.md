# payroll_app.php SQL Injection

## Severity
**High** (CVSS 8.8)

## CVE / CWE
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command
- No public CVE (application-specific, bespoke PHP)

## Category
Compensating Control, `payroll_app.php` is a third-party binary whose source
cannot be modified.

## Description
`payroll_app.php` constructs MySQL queries by directly interpolating POST
parameters without prepared statements or escaping.

An attacker can submit a tautology or UNION-based payload in the `username`
field to bypass authentication or dump the database.

Because the PHP source is locked (binary-distributed, vendor-controlled, or
policy-protected), the SQLi cannot be patched in code.

## Affected Service
- **Service:** Apache2 + payroll_app.php
- **Port:** 80/TCP

## Constraint
`payroll_app.php` must remain running and must accept legitimate username/password
combinations. The compensating control must not disable or replace the application.
