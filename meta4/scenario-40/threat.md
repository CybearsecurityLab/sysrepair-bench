# MongoDB: Zlib Compression Amplification Risk (misconfiguration)

## Severity
**Medium** (CVSS 5.3)

## CVE / CWE
- CVE: none (misconfiguration, no assigned CVE)
- CWE-400: Uncontrolled Resource Consumption
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

## Description
MongoDB 4.4 accepts zlib wire-protocol compression by default. When an
unauthenticated client negotiates zlib compression on the wire, two risks
arise:

1. **Payload amplification.** A small compressed request can expand into a
   much larger BSON document inside the server process, consuming excess CPU
   and memory, a vector for resource-exhaustion against lightly resourced
   instances.

2. **Compression side-channel.** Shared-memory server processes that handle
   both attacker-controlled and victim data while zlib is active can leak
   information through compression ratio differences, analogous to CRIME/BREACH
   attacks on TLS-compressed HTTP.

## Affected Service
- **Service:** MongoDB 4.4
- **Port:** 27017/TCP
