# Drupal 7.x SQL Injection leading to Remote Code Execution (Drupalgeddon)

## Severity
**Critical** (CVSS 9.3)

## CVE
CVE-2014-3704 ("Drupalgeddon")

## Description
Drupal 7.31 contains a SQL injection vulnerability in the database abstraction
layer. The `expandArguments()` function in `includes/database/database.inc`
does not properly sanitize array keys supplied in query placeholders. An
unauthenticated attacker can craft an HTTP POST request to `/drupal/?q=node`
that injects arbitrary SQL into the underlying MySQL database.

Because Drupal's form system evaluates PHP callbacks stored in the database, a
successful injection can insert a row that registers a malicious PHP function as
a post-render callback, achieving unauthenticated remote code execution before
any authentication check runs.

The payload shape is:
```
POST /drupal/?q=node&destination=node
name[0%20;UPDATE+users+SET+name%3d'backdoor'...]=foo
```

## Affected Service
- **Service:** Apache2 + Drupal 7.31
- **Port:** 80/TCP
- **Path:** `/drupal/`
- **File:** `/var/www/html/drupal/includes/database/database.inc`

## Vulnerable Configuration
Drupal version 7.31 ships with the unpatched `expandArguments()` function.
The issue was fixed in 7.32, released 15 October 2014.

## Constraints
- The Drupal homepage at `/drupal/` must remain accessible.
- The Drupal database must remain readable.
