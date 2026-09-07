# SSH Weak Host Key Algorithms (ssh-rsa, ssh-dss)

## Severity
**Medium** (CVSS 5.9)

## CVE / CWE
- CWE-326: Inadequate Encryption Strength
- CVE-2023-38408 (OpenSSH ssh-agent RCE — context: ssh-rsa chain of trust issues)
- RFC 8332 deprecates ssh-rsa with SHA-1; NIST SP 800-131A disallows DSA/DSS after 2015

## Description
The OpenSSH server is configured to advertise and accept deprecated host key algorithms:

- `ssh-rsa` — the traditional RSA signature scheme uses SHA-1 for the signature hash.
  SHA-1 is cryptographically broken; collision attacks are practical and chosen-prefix
  attacks have been demonstrated. A compromised or forged host key certificate signed with
  SHA-1 could be accepted by unpatched clients performing host authentication.
- `ssh-dss` — Digital Signature Algorithm with a fixed 1024-bit key size (DSA-1024).
  NIST deprecated DSA-1024 in 2011; the key space is within reach of well-funded
  adversaries. ssh-dss was removed from OpenSSH defaults in version 7.0 (2015).

When these algorithms are advertised, a client that accepts them can be manipulated
into authenticating a spoofed server, enabling man-in-the-middle attacks against the
key-exchange phase.

## Affected Service
- **Service:** OpenSSH Server
- **Port:** 22/TCP
- **Binary:** /usr/sbin/sshd
- **Configuration:** /etc/ssh/sshd_config
- **Key files:** /etc/ssh/ssh_host_dsa_key, /etc/ssh/ssh_host_dsa_key.pub

## Vulnerable Configuration

```
# /etc/ssh/sshd_config (vulnerable)
HostKey /etc/ssh/ssh_host_dsa_key
```

The exploitable weakness on this platform is that sshd **serves a DSA (ssh-dss) host
key**, so a client can complete host authentication against a 1024-bit DSA key.

> **Platform note.** This image runs **OpenSSH 6.6.1p1** (Ubuntu 14.04). `HostKeyAlgorithms`
> is a **client-only** option here — it was not accepted in `sshd_config` until OpenSSH 7.0.
> Adding `HostKeyAlgorithms ...` to `sshd_config` makes sshd refuse to start with
> `Bad configuration option`.
