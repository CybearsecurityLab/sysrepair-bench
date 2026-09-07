# S7comm — Unauthenticated PLC Access (protocol design flaw)

## Severity
**Critical** (CVSS 9.1)

## CVE / CWE
- CWE-306: Missing Authentication for Critical Function

## Category
Compensating Controls

## Description
The Siemens S7 communication protocol (S7comm) is used by Siemens S7-300/400/1200/1500
PLCs and runs over ISO-TSAP on TCP port 102. Like Modbus, S7comm was designed for
isolated industrial networks and **has no native authentication or encryption**.

Any host that can reach TCP port 102 can:
- Read and write PLC data blocks, inputs, outputs, and memory areas
- Upload or download PLC programs (ladder logic, function blocks)
- Start and stop the PLC CPU
- Cause physical process disruption or equipment damage

The Stuxnet worm exploited unauthenticated S7comm access to reprogram Siemens PLCs
controlling uranium centrifuges. In this scenario the simulator listens on
`0.0.0.0:102`, exposing it to all network interfaces without restriction.

## Affected Service
- **Service:** S7comm TCP simulator
- **Port:** 102/TCP
- **Vulnerable configuration:** server bound to `0.0.0.0` with no firewall

## Constraints
- The PLC must remain running and must keep completing the S7/COTP handshake
  for loopback clients.
