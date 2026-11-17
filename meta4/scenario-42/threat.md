# CouchDB 3.2.1: Default Erlang Cookie RCE (CVE-2022-24706)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-24706
- CWE-1188: Initialization with Insecure Default

## Description
Apache CouchDB is built on the Erlang/OTP runtime, which uses a shared secret
called the "Erlang cookie" to authenticate inter-node communication over the
Erlang distribution protocol. CouchDB 3.2.1 (and earlier releases) ship with
a well-known default cookie value.

An attacker who knows this cookie can connect directly to the Erlang Port
Mapper Daemon (EPMD, default port 4369) and the corresponding distribution
port, then send arbitrary Erlang Remote Procedure Calls to the running node.
This gives unauthenticated remote code execution as the OS user running
CouchDB, with no HTTP credentials, no CouchDB account, and no exploit chain required.

## Affected Service
- **Service:** Apache CouchDB 3.2.1
- **Port:** 5984/TCP (HTTP API), 4369/TCP (EPMD)
