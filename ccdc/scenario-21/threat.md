# Threat: Kernel IP Forwarding Enabled

## Vulnerability
The system has IP forwarding enabled (`net.ipv4.ip_forward = 1`) and ICMP send redirects
enabled (`net.ipv4.conf.all.send_redirects = 1`). This configuration turns the host into
a potential network router, allowing it to forward packets between network interfaces.
Combined with send_redirects, an attacker who compromises this host can perform
man-in-the-middle attacks by redirecting traffic through the compromised machine.

## CWE Classification
- **CWE-1188**: Insecure Default Initialization of Resource

## Affected Configuration
- `/etc/sysctl.conf` contains:
  - `net.ipv4.ip_forward = 1`
  - `net.ipv4.conf.all.send_redirects = 1`
  - `net.ipv4.conf.default.send_redirects = 1`

## Source
- TAMU sysctl.sh
- UTSA script.sh
