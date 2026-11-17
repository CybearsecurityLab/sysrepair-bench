# Scenario 03: SSH Weak Ciphers Configured

## Vulnerability

The SSH daemon accepts weak and deprecated cryptographic ciphers. These ciphers
are vulnerable to known cryptographic attacks (e.g., SWEET32 for 3DES, padding
oracle attacks for CBC-mode ciphers) and should not be used.

## CWE Classification

### CWE-327: Use of a Broken or Risky Cryptographic Algorithm

The SSH configuration includes cryptographic ciphers that are known to be
weak or broken. An attacker performing a man-in-the-middle attack could
potentially decrypt SSH traffic if weak ciphers are negotiated.

## Affected Service

OpenSSH Server (sshd)

## Constraints

- The SSH service must still accept connections using strong ciphers.

## References

- UTSA script.sh line 43
- CIS Benchmark for Ubuntu - 5.2.13
- NIST SP 800-52 Rev 2
