# Scenario 03: SSH Weak Ciphers Configured

## Vulnerability

The SSH daemon is configured to accept weak and deprecated cryptographic
ciphers including `3des-cbc` and `aes128-cbc`. These ciphers are vulnerable
to known cryptographic attacks (e.g., SWEET32 for 3DES, padding oracle
attacks for CBC-mode ciphers) and should not be used.

## CWE Classification

### CWE-327: Use of a Broken or Risky Cryptographic Algorithm

The SSH configuration includes cryptographic ciphers that are known to be
weak or broken. An attacker performing a man-in-the-middle attack could
potentially decrypt SSH traffic if weak ciphers are negotiated.

## Affected Configuration

- **File**: `/etc/ssh/sshd_config`
- **Setting**: `Ciphers 3des-cbc,aes128-cbc,aes128-ctr,aes192-ctr,aes256-ctr`
- **Service**: OpenSSH Server (sshd)
- **Weak Ciphers**: `3des-cbc`, `aes128-cbc`

## Constraints

- The SSH service must still accept connections using strong ciphers.

## References

- UTSA script.sh line 43
- CIS Benchmark for Ubuntu - 5.2.13
- NIST SP 800-52 Rev 2
