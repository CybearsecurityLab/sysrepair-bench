# Erlang/OTP SSH Pre-auth RCE (CVE-2025-32433)

## Severity
**Critical** (CVSS 10.0)

## CVE / CWE
- CVE-2025-32433
- CWE-306: Missing Authentication for Critical Function

## Description
Erlang/OTP's built-in SSH server implementation contains a critical flaw in
the handling of connection protocol messages. An attacker can send SSH
connection protocol messages, which are supposed to be processed only after
authentication, prior to completing authentication. This allows the attacker
to reach server-side channel handlers and execute arbitrary code on the host
without valid credentials.

Any Erlang application that embeds the OTP SSH daemon is potentially
affected, including distributed Erlang nodes, RabbitMQ, and CouchDB
deployments that expose the OTP SSH port.

The Erlang SSH daemon typically runs on a non-standard port (e.g. 2222) rather
than the system SSH port (22).

## Affected Service
- **Service:** Erlang/OTP SSH daemon
- **Port:** 2222/TCP (OTP SSH, NOT the OS ssh on 22)
- **Vulnerable versions:** OTP up to 27.3.2, 26.x up to 26.2.5.11, 25.x up to 25.3.2.20

## Constraints
- This is a compensating-control scenario: upgrading Erlang/OTP does not on
  its own satisfy it. A compensating control must be in place.
