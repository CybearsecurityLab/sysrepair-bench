# phpMyAdmin Admin Interface Exposed: Cleartext HTTP, No Source Restriction

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-319: Cleartext Transmission of Sensitive Information
- CWE-284: Improper Access Control
- OpenVAS: "Cleartext Transmission of Sensitive Information via HTTP" — `/phpmyadmin/:pma_password`

## Description
The phpMyAdmin login interface at `/phpmyadmin/` is served over cleartext HTTP
and accepts connections from any remote IP address. Two distinct weaknesses are
present:

1. **Cleartext transmission:** The login form POSTs `pma_password` (the MySQL
   password) over plain HTTP. Any network observer positioned between the client
   and the server — on a shared LAN, through a rogue access point, or via ARP
   spoofing — can capture the credential in cleartext from a single packet
   capture.

2. **No source restriction:** The Apache configuration places no `Require ip`
   or `Order`/`Allow` directive on `/phpmyadmin/`. The administration interface
   is therefore reachable from any routable IP, exposing MySQL management
   capabilities (arbitrary SQL, file read/write via `LOAD DATA INFILE`,
   `INTO OUTFILE`) to the entire network.

Together these weaknesses mean a remote attacker can both intercept credentials
and use them directly to gain unrestricted MySQL access.

## Affected Service
- **Service:** Apache2 + phpMyAdmin 3.5.8
- **Port:** 80/TCP
- **Path:** `/phpmyadmin/`

## Vulnerable Configuration
```
# /etc/apache2/conf.d/phpmyadmin.conf (or equivalent)
# No Require / Allow directive present — all sources accepted
Alias /phpmyadmin /var/www/phpmyadmin
```
