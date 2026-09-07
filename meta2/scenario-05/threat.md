# FTP Unencrypted Cleartext Login

## Severity
**Medium** (CVSS 4.8)

## CVE
N/A (protocol/configuration weakness)

## Description
The FTP server (vsftpd) on this system transmits all data, including user credentials,
in cleartext over the network. The FTP protocol (RFC 959) was designed without built-in
encryption, meaning that usernames, passwords, and file contents are sent as plaintext.

Without SSL/TLS encryption (FTPS), an attacker on the same network segment can trivially
capture FTP credentials using passive network sniffing tools such as tcpdump, Wireshark,
or ettercap. This is especially dangerous in shared network environments, wireless networks,
or any scenario where an attacker can perform ARP spoofing or traffic interception.

The captured credentials can then be used to:
- Access the FTP server with the victim's privileges
- Pivot to other services if the user reuses passwords
- Download or tamper with sensitive files

## Affected Service
- **Service:** vsftpd (Very Secure FTP Daemon)
- **Port:** 21/TCP
- **Binary:** /usr/sbin/vsftpd
- **Configuration:** /etc/vsftpd.conf

## Vulnerable Configuration
```
# /etc/vsftpd.conf
# ssl_enable is not set (defaults to NO)
# No TLS/SSL configuration present
# All FTP traffic is transmitted in cleartext
```
