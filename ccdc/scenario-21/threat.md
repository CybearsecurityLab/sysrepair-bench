# Threat: Kernel IP Forwarding Enabled

## Vulnerability
The system has IP forwarding and ICMP send redirects enabled in its kernel network
parameters. This configuration turns the host into a potential network router,
allowing it to forward packets between network interfaces. Combined with send
redirects, an attacker who compromises this host can perform man-in-the-middle
attacks by redirecting traffic through the compromised machine.

## CWE Classification
- **CWE-1188**: Insecure Default Initialization of Resource

## Source
- TAMU sysctl.sh
- UTSA script.sh
