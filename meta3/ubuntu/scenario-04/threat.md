# CUPS HTTPS Exposes Vulnerable Cipher Suites (SWEET32 3DES, RC4)

## Severity
**High** (CVSS 7.5)

## Category
Compensating Control

## Constraint
**CUPS must remain at 1.7.2** (the platform-provided version; no upgrade path exists on
trusty). The agent must eliminate the weak cipher exposure without changing the CUPS package.
The real CUPS service must remain reachable on port 631.

## CVE / CWE
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- CVE-2016-2183 (SWEET32 — birthday attack on 64-bit block ciphers, affects 3DES-CBC)
- CVE-2015-2808 (RC4 NOMORE — plaintext recovery from RC4 streams)
- CVE-2013-2566 (RC4 statistical biases allowing session key recovery)

## Description
The CUPS printing service HTTPS endpoint on port 631 is configured to allow cipher suites
that use the RC4 stream cipher and 3DES block cipher:

- **RC4 (AllowRC4):** RC4 is a stream cipher with well-documented statistical biases.
  The RC4 NOMORE attack (CVE-2015-2808) can recover HTTP session cookies from long-lived
  TLS connections. IETF RFC 7465 prohibits RC4 in TLS. NIST removed RC4 from approved
  algorithms in 2015.
- **3DES / SWEET32 (implicit in AllowDH with default cipher lists):** 3DES-CBC uses a
  64-bit block size. The SWEET32 attack (CVE-2016-2183) exploits birthday-bound
  collisions: after approximately 2^32 blocks (~785 GB) an attacker can recover XOR of
  two plaintext blocks, enabling cookie injection or session hijacking against long-lived
  HTTPS connections such as the CUPS web admin interface.
- **Anonymous DH (AllowDH without authentication):** Cipher suites with anonymous
  Diffie-Hellman provide no server authentication, enabling trivial man-in-the-middle
  attacks. These suites have been prohibited by RFC 4346 since 2006.

## Affected Service
- **Service:** CUPS (Common Unix Printing System)
- **Port:** 631/TCP (HTTPS)
- **Binary:** /usr/sbin/cupsd
- **Configuration:** /etc/cups/cupsd.conf

## Vulnerable Configuration

```
# /etc/cups/cupsd.conf (vulnerable)
SSLOptions AllowRC4 AllowDH
```
