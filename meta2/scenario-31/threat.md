# rlogin Passwordless/Unencrypted Service Vulnerability

## Threat Details

**Severity:** High
**CVSS Score:** 7.5
**CVE:** CVE-1999-0651

## Description

The rlogin (remote login) service is a legacy BSD remote access protocol that suffers from multiple critical security flaws:

1. **No Encryption**: All traffic including authentication credentials is transmitted in cleartext
2. **Weak Authentication**: Relies on `.rhosts` and `/etc/hosts.equiv` files for trust-based authentication
3. **Passwordless Login**: Can allow access without any password if trust relationships are configured
4. **Host-Based Authentication**: Trusts the client-provided hostname without cryptographic verification

## Affected Service

- **Service:** rlogind (Remote Login Daemon)
- **Port:** 513/tcp
- **Protocol:** rlogin (unencrypted, obsolete)

## Vulnerable Configuration

The rlogin service is enabled in xinetd with a dangerous `/etc/hosts.equiv` configuration:

```
/etc/hosts.equiv:
+ +
```

This configuration allows **ANY user from ANY host** to login without a password.

## Impact

An attacker can:
- Login to the system without any password from any machine
- Intercept all rlogin traffic including credentials using network sniffing
- Spoof trusted hostnames to gain unauthorized access
- Execute arbitrary commands remotely
- Achieve complete system compromise through unauthenticated root access

This is one of the most severe misconfigurations possible on a Unix system.
