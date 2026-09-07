# Cleartext Transmission of Sensitive Information via HTTP

## Severity
**Medium** (CVSS 4.8)

## CVE
CWE-319 (Cleartext Transmission of Sensitive Information)

## Description
The Apache web server on this system serves login forms and phpMyAdmin over unencrypted
HTTP. Sensitive information such as usernames, passwords, session tokens, and database
queries are transmitted in cleartext across the network. An attacker on the same network
segment can passively sniff traffic to capture credentials and session cookies, or perform
active man-in-the-middle attacks to inject malicious content.

phpMyAdmin provides direct database administration access, and its login form is also served
over HTTP, meaning database credentials are exposed in transit.

## Affected Service
- **Service:** Apache HTTP Server 2.2 with PHP5 and phpMyAdmin
- **Port:** 80/TCP
- **Binary:** /usr/sbin/apache2
- **Configuration:** /etc/apache2/sites-available/default

## Vulnerable Configuration
Apache is configured with only HTTP (port 80) enabled. There is no SSL/TLS configuration:

```
# /etc/apache2/sites-available/default
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www
    # No HTTPS redirect, no SSL configuration
</VirtualHost>
```

The `ssl` module is not enabled, and no certificates are installed. All traffic including
login forms and phpMyAdmin sessions are served in cleartext.
