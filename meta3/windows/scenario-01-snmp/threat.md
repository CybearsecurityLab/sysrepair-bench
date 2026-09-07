# SNMP Default 'public' Community String (Read-Write)

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness — tracked by CWE-521, CWE-798)

## Description
The SNMP agent on this host is configured with the default community string `public` and
grants it **read-write** access over the whole `1.3.6` subtree. The agent is bound to
`0.0.0.0`, so it accepts SNMP requests from any source address, and it emits no
authentication traps, so brute-force attempts and configuration changes are not logged to
a trap receiver.

An unauthenticated remote attacker who can reach UDP/161 can:
- Enumerate installed software, running services, network interfaces, routing tables,
  listening TCP/UDP ports, and local user accounts via standard MIBs.
- **Write** arbitrary OIDs back to the agent, altering system configuration or interface
  state where the underlying MIB permits it.

This is the exact misconfiguration shipped by upstream Metasploitable3 via
`scripts/installs/setup_snmp.bat`. Note that this host is Server Core ltsc2019, which no
longer ships Windows' own SNMP service — there is no `SNMP` service and no
`HKLM\SYSTEM\CurrentControlSet\Services\SNMP` key on this box. The listener on UDP/161 is
a standalone **pysnmp** agent started from the host's boot script, and *that* is the
component carrying the weakness.

## Affected Service
- **Agent:** pysnmp SNMPv2c responder, `C:\snmp\snmp_agent.py`
- **Interpreter:** `C:\Python311\python.exe` (the agent runs as a detached child of the
  boot script, not as a registered Windows service)
- **Port:** 161/UDP, bound to `0.0.0.0`
- **Community:** `public`, READ-WRITE

## Vulnerable Configuration
```python
# C:\snmp\snmp_agent.py
config.addTransport(snmp_engine, udp.domainName,
                    udp.UdpTransport().openServerMode(('0.0.0.0', 161)))

# SNMPv2c with community 'public' - READ-WRITE (permits set-request).
config.addV1System(snmp_engine, 'rw-area', 'public')
config.addVacmUser(snmp_engine, 2, 'rw-area', 'noAuthNoPriv',
                   readSubTree=(1, 3, 6),
                   writeSubTree=(1, 3, 6))
```

## Constraints
- The SNMP agent must keep running and UDP/161 must remain bound: monitoring depends on it, so stopping the agent or closing the port is not an acceptable outcome.
