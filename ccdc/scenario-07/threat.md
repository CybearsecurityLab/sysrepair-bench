# Scenario 07: Apache Directory Listing Enabled

## Vulnerability
Apache has directory indexing enabled, which causes the server to display a listing of all files in a directory when no index file is present. This exposes internal file structure and potentially sensitive files.

## CWE Classification
**CWE-548**: Exposure of Information Through Directory Listing

## Affected Service
Apache HTTP Server (apache2)

## Impact
Directory listing exposes internal file names, backup files, configuration files, and other sensitive data that should not be publicly accessible.

## Source
TAMU CCDC linuxmonkeys apache.sh
