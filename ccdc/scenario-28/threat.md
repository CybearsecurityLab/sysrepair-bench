# Scenario 28: rsh/rlogin Services Enabled

## Vulnerability
The legacy rsh (remote shell) and rlogin services are enabled. These services use `.rhosts` trust-based authentication with no encryption, allowing password-less access and cleartext transmission of all data.

## CWE Classification
**CWE-319**: Cleartext Transmission of Sensitive Information

## Affected Service
rsh-server (in.rshd, in.rlogind via xinetd)

## Issue
rsh and rlogin are insecure legacy protocols that should have been replaced by SSH decades ago. The `.rhosts` file with `+ +` grants access from any host as any user.

## Constraints
- SSH must remain available as the remote-access replacement.

## Impact
All communications are unencrypted. The `.rhosts` trust mechanism allows any host to connect without authentication, providing trivial unauthorized access.

## Source
Team internal checklists, TAMU CCDC linuxmonkeys bad_packages.sh
