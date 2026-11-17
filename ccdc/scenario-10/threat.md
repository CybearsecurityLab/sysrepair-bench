# Scenario 10: Nginx Directory Listing Enabled

## Vulnerability
Nginx has automatic directory indexing enabled, which displays directory contents when no index file is present. This exposes internal file structure and potentially sensitive files to anyone who can access the web server.

## CWE Classification
**CWE-548**: Exposure of Information Through Directory Listing

## Affected Service
Nginx

## Impact
Directory listing exposes file names, sizes, and modification dates, potentially revealing sensitive files such as backup files, configuration files, and credential stores.

## Source
TAMU CCDC linuxmonkeys harden_nginx.sh
