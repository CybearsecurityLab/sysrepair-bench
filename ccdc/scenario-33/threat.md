# Scenario 33: Outdated OpenSSL Library

## Vulnerability

The system is running an outdated version of OpenSSL that has been held back from security updates. The OpenSSL package is prevented from upgrading, leaving it vulnerable to known cryptographic weaknesses and CVEs. Outdated OpenSSL can be exploited for TLS downgrade attacks, padding oracle attacks, and other cryptographic vulnerabilities.

## CWE Classification

- **CWE-327**: Use of a Broken or Risky Cryptographic Algorithm
- Running an outdated OpenSSL version means known-vulnerable cipher implementations remain in use.

## Affected Components

- `openssl` package - Held at an older version
- `libssl3` / `libssl3t64` - Shared library held back

## Constraints

- TLS connections must continue to work.

## References

- CIS Ubuntu Linux Benchmark - Section 1.9
- NIST SP 800-52 (Guidelines for TLS Implementations)
- TAMU check_openssl_date.sh
