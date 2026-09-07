# Modbus/TCP — Unauthenticated PLC Access (protocol design flaw)

## Severity
**Critical** (CVSS 9.1)

## CVE / CWE
- CWE-306: Missing Authentication for Critical Function

## Category
Compensating Controls

## Description
Modbus/TCP is an industrial control system (ICS) protocol designed in 1979 for
serial communication and later adapted for TCP/IP networks. The protocol has
**no native authentication, encryption, or access control** — any host that
can reach TCP port 502 can send arbitrary Modbus commands.

In this scenario the Modbus server listens on `0.0.0.0:502`, meaning any
network-reachable client can read or write PLC holding registers without
credentials. An attacker can:
- Read sensor values and setpoints (reconnaissance)
- Write arbitrary register values to manipulate physical processes
- Cause equipment damage or safety incidents

## Affected Service
- **Service:** pyModbusTCP simulated PLC
- **Port:** 502/TCP
- **Vulnerable configuration:** server bound to `0.0.0.0` with no firewall

## Constraints
- The PLC must remain running and must keep answering Modbus holding-register
  reads from loopback.
