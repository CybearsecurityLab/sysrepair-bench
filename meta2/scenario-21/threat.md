# OpenSSL CCS Injection Vulnerability (Man-in-the-Middle)

## Severity
**Medium** -- CVSS 6.8

## CVE
CVE-2014-0224

## Description
OpenSSL versions before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h do not properly restrict processing of ChangeCipherSpec (CCS) messages. This allows man-in-the-middle attackers to trigger use of a zero-length master key in certain OpenSSL-to-OpenSSL communications by crafting a CCS message before the key exchange is complete. This effectively allows decryption and modification of encrypted traffic.

Ubuntu 8.04 ships OpenSSL 0.9.8g, which is well below the patched version 0.9.8za. Any service using this OpenSSL library for TLS/SSL (such as PostgreSQL with SSL enabled) is vulnerable.

## Affected Service / Port
- **Service:** PostgreSQL (with SSL enabled)
- **Port:** 5432

## Vulnerable Version
- OpenSSL < 0.9.8za
- OpenSSL 1.0.0 < 1.0.0m
- OpenSSL 1.0.1 < 1.0.1h
- Ubuntu 8.04 ships OpenSSL 0.9.8g
