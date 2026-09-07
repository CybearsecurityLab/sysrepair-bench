# Scenario 29: No Firewall Installed (ufw Absent)

## Vulnerability
The system has no firewall installed or configured. All network ports are exposed directly without any filtering, allowing unrestricted inbound and outbound network access.

## CWE Classification
**CWE-1188**: Insecure Default Initialization of Resource

## Affected Service
System-wide (no firewall)

## Issue
Without a firewall, all running services are directly accessible from the network. There is no defense-in-depth against unauthorized access.

## Constraints
- The necessary services, SSH and HTTP, must remain reachable.

## Impact
All services are exposed to the network without any filtering. An attacker can directly access any listening port, and compromised applications have unrestricted outbound network access.

## Source
TAMU CCDC linuxmonkeys firewall.sh
