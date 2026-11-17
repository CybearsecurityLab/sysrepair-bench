# Scenario 15: vsftpd Anonymous Upload Enabled

## Vulnerability
vsftpd is configured to allow anonymous users to upload files and create directories. This allows anyone to upload arbitrary files to the server without authentication.

## CWE Classification
**CWE-434**: Unrestricted Upload of File with Dangerous Type

## Affected Service
vsftpd (Very Secure FTP Daemon)

## Impact
Anonymous users can upload malware, web shells, or other malicious content to the server. Combined with a web server, this could lead to remote code execution.

## Source
TAMU CCDC linuxmonkeys vsftpd.sh
