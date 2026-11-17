# SSH Weak Encryption Algorithms

## Severity
**Medium** (CVSS 4.3)

## CVE
N/A (configuration weakness)

## Description
The OpenSSH server on this system is configured to allow weak and deprecated encryption
algorithms. The default configuration of OpenSSH on Ubuntu 8.04 enables CBC-mode ciphers
and RC4-based ciphers (arcfour). These algorithms are vulnerable to known
cryptographic attacks:

- **CBC ciphers** are susceptible to the CPNI-957037 plaintext recovery attack, which can
  allow an attacker to recover up to 32 bits of plaintext from an arbitrary block of
  ciphertext from a connection secured using the SSH protocol.
- **RC4/arcfour** ciphers have known statistical biases that weaken confidentiality.

An attacker performing a man-in-the-middle attack could exploit these weaknesses to
partially decrypt SSH traffic.

## Affected Service
- **Service:** OpenSSH Server
- **Port:** 22/TCP
