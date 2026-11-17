# SSH Default Credentials

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness / default credentials)

## Description
The SSH server on this system has multiple user accounts configured with weak, default, or
easily guessable passwords. This is a direct replica of the Metasploitable 2 configuration
where several accounts use the username as the password, including the administrative and
root accounts.

With password authentication enabled, these accounts are trivially compromised via
brute-force or credential-stuffing attacks. An attacker with network access to port 22 can
gain full shell access to the system within seconds.

## Affected Service
- **Service:** OpenSSH Server
- **Port:** 22/TCP
