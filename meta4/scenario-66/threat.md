# IPMI — Cipher-Zero Authentication Bypass (protocol design flaw)

## Severity
**Critical** (CVSS 10.0)

## CVE / CWE
- CWE-306: Missing Authentication for Critical Function
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm

## Category
Compensating Controls

## Description
The Intelligent Platform Management Interface (IPMI) is a hardware-level
management protocol used for out-of-band server control (power, console,
sensors). IPMI 2.0 introduced RAKP authentication, but **cipher suite 0
(null cipher) was included as a mandatory implementation requirement**, allowing
any client to authenticate with any username and any password — the credentials
are never verified.

When UDP port 623 is exposed on `0.0.0.0`, any network-adjacent attacker can:
- Log in to the BMC as administrator using cipher 0 with any password
- Power off, reset, or PXE-boot the host
- Read/write arbitrary memory via the BMC's hardware access
- Exfiltrate IPMI credential hashes for offline cracking (RAKP hash leak)

This affects virtually all server BMCs shipped before ~2015 (Dell iDRAC,
HP iLO, Supermicro IPMI, etc.). On this host, cipher suite 0 is enabled in the
`cipher_suite_ids` list in `/etc/ipmi.conf`, so the BMC permits the
authentication bypass described above.

## Affected Service
- **Service:** IPMI BMC (simulated)
- **Port:** 623/UDP
- **Vulnerable configuration:** cipher_suite_ids includes 0, bound to 0.0.0.0
