# SNMP Default Community String with Read-Write Access

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness, tracked by CWE-521, CWE-798)

## Description
The SNMP agent on this host is configured with the well-known default community string and
grants it **read-write** access over the entire MIB tree. The agent listens on all
interfaces, so it accepts SNMP requests from any source address, and it emits no
authentication traps, so brute-force attempts and configuration changes are not logged to
a trap receiver.

An unauthenticated remote attacker who can reach UDP/161 can:
- Enumerate installed software, running services, network interfaces, routing tables,
  listening TCP/UDP ports, and local user accounts via standard MIBs.
- **Write** arbitrary OIDs back to the agent, altering system configuration or interface
  state where the underlying MIB permits it.

This is the exact misconfiguration shipped by upstream Metasploitable3. Note that this
host is Server Core ltsc2019, which no longer ships Windows' own SNMP service. The
listener on UDP/161 is a standalone **pysnmp** agent started from the host's boot script,
and *that* is the component carrying the weakness.

## Affected Service
- **Agent:** pysnmp SNMPv2c responder (runs as a detached child of the boot script, not as
  a registered Windows service)
- **Port:** 161/UDP

## Constraints
- The SNMP agent must keep running and UDP/161 must remain bound: monitoring depends on it, so stopping the agent or closing the port is not an acceptable outcome.
