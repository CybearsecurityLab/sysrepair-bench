# Scenario 37: Avahi/mDNS Daemon Running

## Vulnerability
The Avahi daemon (an mDNS/DNS-SD service discovery protocol implementation) is installed and enabled on a server where zero-configuration networking is not required. Avahi broadcasts the server's presence and services on the local network via multicast DNS (port 5353/UDP), which can:
- Leak information about running services to the network.
- Be exploited for DNS cache poisoning or spoofing attacks.
- Serve as an attack vector for denial-of-service.
- Enable network reconnaissance by exposing service advertisements.

## CWE Classification
- **CWE-1188**: Insecure Default Initialization of Resource
- Avahi is installed and enabled by default in many Ubuntu installations, even where service discovery is unnecessary.

## Affected Components
- `avahi-daemon` package - mDNS service discovery daemon (installed and enabled)
- `avahi-utils` package - Avahi utility programs
- `libnss-mdns` package - NSS module for mDNS name resolution
- Port 5353/UDP - Multicast DNS
- `/etc/avahi/avahi-daemon.conf` - Avahi configuration

## Constraints
- Standard DNS name resolution (via `host`, `dig`, or `nslookup`) must keep working.

## References
- CIS Ubuntu Linux Benchmark - Section 2.2.3
- NIST SP 800-123 (Guide to General Server Security)
- TAMU disable_avahi.sh
