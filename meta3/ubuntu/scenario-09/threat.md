# jQuery < 1.9.0 XSS in Drupal-Shipped Assets (CVE-2012-6708)

## Severity
**Medium** (CVSS 6.1)

## CVE
CVE-2012-6708

## Description
Drupal 7.31 ships jQuery 1.4.4 at `/drupal/misc/jquery.js`. jQuery versions
before 1.9.0 are vulnerable to a cross-site scripting flaw in the `$.html()`
selector function: when a string beginning with a hash character is passed as a
selector, jQuery evaluates it as HTML rather than as a DOM query. An attacker
can craft a URL or inject a fragment identifier that causes arbitrary JavaScript
to execute in the context of the Drupal application origin.

The vulnerable code path is:
```javascript
// jQuery < 1.9.0: this evaluates user-supplied HTML
$( location.hash )
```

Any page on the Drupal site that passes `location.hash` or a user-controlled
string to a jQuery selector is exploitable. Attackers can steal session cookies,
perform actions as the authenticated user, or redirect the browser to a phishing
page.

## Affected Service
- **Service:** Apache2 + Drupal 7.31
- **Port:** 80/TCP
- **Asset:** `/drupal/misc/jquery.js`

## Vulnerable Configuration
```
/var/www/html/drupal/misc/jquery.js — jQuery 1.4.4
```
The bundled jQuery version can be confirmed with:
```bash
head -3 /var/www/html/drupal/misc/jquery.js
# jQuery JavaScript Library v1.4.4
```
