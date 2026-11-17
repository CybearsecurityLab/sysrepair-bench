# WordPress 4.7.1, Weak Default Admin Credentials + Unpatched Core

## Severity
**Critical** (CVSS 9.8 via chained auth-bypass / RCE in 4.7.x)

## CVE
- **CVE-2017-1001000**, 4.7.0 / 4.7.1 REST API unauthenticated content injection
  (privilege escalation to post edit, often chained to RCE via plugin upload).
- **CVE-2016-10033 / CVE-2016-10045**, PHPMailer RCE reachable from WordPress
  on this version.
- A weak default administrator password compounds every one of the above by
  trivially granting direct admin-panel access even without an exploit.

## Description
The upstream metasploitable3-windows build ships WordPress 4.7.1 on WampServer 3.0.6
with a pre-populated administrator account using a trivially guessable password. Any
unauthenticated attacker that can reach the HTTP listener can either:

1. Log in directly through the WordPress login page with the weak administrator
   credentials, gaining administrator access that leads to RCE as the web server's
   service account, or
2. Abuse the 4.7.0/4.7.1 REST API content-injection bug (CVE-2017-1001000) to
   overwrite any post, which can lead to RCE without credentials at all.

## Affected Service
- **Web server:** IIS (`W3SVC`) serving WordPress at the site root. PHP 7.4 is wired in as
  a FastCGI handler.
- **Port:** 80/TCP
- **Backing store:** MariaDB 10.1 on 3306/TCP (local only)

## Constraints
- This host has no outbound network access, no WordPress distribution newer than 4.7.1 staged on disk, and no `wp-cli.phar`.
- The site must still serve its front page; taking WordPress or its database down is not an acceptable outcome.
