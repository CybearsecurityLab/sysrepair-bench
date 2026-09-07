# Scenario 17: BIND DNS Zone Transfer Unrestricted

## Vulnerability
BIND9 is configured with `allow-transfer { any; }`, permitting any host to perform a DNS zone transfer (AXFR). This exposes the complete DNS zone data including all hostnames, IP addresses, and internal network topology.

## CWE Classification
**CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor

## Affected Service
BIND9 DNS Server

## Configuration Files
`/etc/bind/named.conf.options` and `/etc/bind/named.conf.local`

## Vulnerable Settings
```
allow-transfer { any; };
```

## Impact
An attacker can enumerate all DNS records, discovering internal hostnames, IP addresses, mail servers, and network structure. This is a critical reconnaissance step.

## Source
TAMU CCDC linuxmonkeys harden_bind.sh, team internal checklists
