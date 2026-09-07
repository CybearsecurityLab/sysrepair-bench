# BIND 9.18 — No DNSSEC Validation (misconfig)

## Severity
**Medium** (CVSS 5.9)

## CVE / CWE
- CWE-345: Insufficient Verification of Data Authenticity

## Description
BIND 9.18 is configured with `dnssec-validation no;` in `named.conf.options`.
When DNSSEC validation is disabled, the resolver accepts DNS responses without
verifying their cryptographic signatures. This leaves all clients that use
this resolver vulnerable to DNS cache poisoning attacks.

In a cache poisoning attack, an attacker races to inject a forged DNS response
before the legitimate authoritative answer arrives. Without DNSSEC validation,
the resolver has no way to distinguish a signed, authentic record from a
crafted, malicious one. A successful attack can redirect users of the resolver
to attacker-controlled IP addresses for any domain — silently redirecting
traffic for banking sites, email servers, software update endpoints, or
internal services.

The Kaminsky attack (2008) demonstrated that cache poisoning is practical
even against well-randomised resolvers.

With `dnssec-validation no`:
- Forged A records are accepted without question
- NXDOMAIN responses can be fabricated to deny legitimate domains
- MX poisoning can redirect all outbound email to attacker mail servers

## Affected Service
- **Service:** BIND 9.18
- **Port:** 53/UDP, 53/TCP
- **Vulnerable configuration:** `dnssec-validation no;` in named.conf.options

## Vulnerable Configuration
```
options {
    dnssec-validation no;
};
```
