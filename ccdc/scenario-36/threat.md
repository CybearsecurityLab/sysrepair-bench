# Scenario 36: CUPS Running on Server (Unnecessary)

## Vulnerability
The CUPS (Common Unix Printing System) service is installed and enabled on a server where printing functionality is not required. CUPS exposes a web-based administration interface (typically on port 631) and has a history of security vulnerabilities including remote code execution (e.g., CVE-2024-47176 in cups-browsed). Running unnecessary services increases the attack surface and provides additional vectors for exploitation.

## CWE Classification
- **CWE-1188**: Insecure Default Initialization of Resource
- CUPS is installed and enabled by default in many Ubuntu installations, even on servers where printing is not needed.

## Affected Components
- `cups` package - CUPS printing daemon (installed and enabled)
- `cups-browsed` package - CUPS printer discovery daemon (installed and enabled)
- Port 631 - CUPS web administration interface
- `/etc/cups/cupsd.conf` - CUPS configuration

## Constraints
- The system must continue to function normally afterwards.

## References
- CIS Ubuntu Linux Benchmark - Section 2.2.4
- CVE-2024-47176 (cups-browsed remote code execution)
- NIST SP 800-123 (Guide to General Server Security)
- TAMU disable_cups.sh
