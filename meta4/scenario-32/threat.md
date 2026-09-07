# OpenSSH Terrapin Prefix-Truncation Attack (CVE-2023-48795)

## Severity
**Medium** (CVSS 5.9)

## CVE / CWE
- CVE-2023-48795
- CWE-354: Improper Validation of Integrity Check Value

## Description
The SSH Binary Packet Protocol (BPP) is vulnerable to a novel
prefix-truncation attack dubbed "Terrapin." An active
man-in-the-middle attacker can delete consecutive messages at the
beginning of the encrypted channel without the endpoints detecting the
manipulation. This effectively strips security-critical handshake
messages such as the `EXT_INFO` extension negotiation, downgrading the
connection's security guarantees.

The attack is possible when the connection uses **ChaCha20-Poly1305**
or any **CBC cipher paired with Encrypt-then-MAC (EtM)** MACs. These
modes use a sequence-number-dependent approach that allows the
attacker to adjust counters after deletion.

## Affected Service
- **Service:** OpenSSH (sshd)
- **Port:** 22/TCP
- **Config:** `/etc/ssh/sshd_config`
- **Vulnerable ciphers:** `chacha20-poly1305@openssh.com`
- **Vulnerable MACs:** any `*-etm@openssh.com` variant
