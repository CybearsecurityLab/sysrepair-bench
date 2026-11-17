# Ingreslock Backdoor Service (Port 1524)

## Threat Details

**Severity:** Critical
**CVSS Score:** 10.0
**CVE:** N/A (deliberate backdoor)

## Description

The "Ingreslock" backdoor is a malicious root shell bound to TCP port 1524. This is one of the most notorious backdoors found on the original Metasploitable 2 vulnerable VM. When an attacker connects to port 1524, they receive an unauthenticated root shell with full system access. It is a persistent backdoor that restarts automatically if the connection is closed.

## Affected Service

- **Service:** Backdoor root shell (netcat listener)
- **Port:** 1524/tcp

## Impact

An attacker who discovers this backdoor can:
- Obtain immediate **unauthenticated root shell access**
- Execute arbitrary commands as the root user
- Read, modify, or delete any file on the system
- Install additional malware or persistence mechanisms
- Pivot to other systems on the network
- Exfiltrate sensitive data
- Completely compromise system integrity, confidentiality, and availability

This represents **total system compromise** and is the highest severity vulnerability possible.
