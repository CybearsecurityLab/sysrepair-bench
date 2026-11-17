# Scenario 16: vsftpd No SSL/TLS Enforcement

## Vulnerability
vsftpd is configured without SSL/TLS, meaning all FTP traffic (including credentials) is transmitted in cleartext. This allows network eavesdroppers to capture usernames, passwords, and file contents.

## CWE Classification
**CWE-319**: Cleartext Transmission of Sensitive Information

## Affected Service
vsftpd (Very Secure FTP Daemon)

## Impact
Usernames, passwords, and all transferred file data are visible to any attacker who can sniff network traffic (MITM, network tap, ARP spoofing).

## Source
TAMU CCDC linuxmonkeys vsftpd.sh
