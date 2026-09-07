# Drupal 7.31 — Drupalgeddon SQL Injection RCE (CVE-2014-3704)

## Severity
**Critical** (CVSS 9.3) — vulnerability; WAF reduces exploitability to Medium

## CVE
CVE-2014-3704 ("Drupalgeddon")

## Category
Compensating Control — Drupal cannot be upgraded to 7.32+ because a legacy
module in this environment is incompatible with the patched database abstraction
layer. The agent must leave Drupal 7.31 in place.

## Description
Drupal 7.31 is vulnerable to CVE-2014-3704 (Drupalgeddon), a SQL injection
flaw in `includes/database/database.inc` that allows unauthenticated remote
code execution. Because this deployment has a hard dependency on a module that
breaks under Drupal 7.32+, upgrading the core is forbidden.

The distinctive Drupalgeddon payload shapes are:
- POST body key pattern: `name[0 ;...]=` (space-semicolon array injection)
- Query-string pattern: `q[%23post_render][]=` (PHP callback registration)

## Affected Service
- **Service:** Apache2 + Drupal 7.31 (pinned)
- **Port:** 80/TCP
- **Path:** `/drupal/`

## Constraint
Drupal must remain at version 7.31. The remediation must not upgrade, remove, or
disable the Drupal application. Only network-layer or Apache-layer controls are
permitted. Legitimate Drupal form submissions (e.g. node/add, user login) must
continue to pass through unimpeded.
