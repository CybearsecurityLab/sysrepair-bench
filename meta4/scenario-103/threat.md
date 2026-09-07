# cups-browsed — RCE via Malicious Printer Advertisement (CVE-2024-47177)

## Severity
**High** (CVSS 9.0)

## CVE / CWE
- CVE-2024-47177 (cups-browsed component of the broader cups-filters RCE chain)
- CWE-77: Improper Neutralisation of Special Elements used in a Command ('Command Injection')

## Description
`cups-browsed` is a daemon that automatically discovers and creates local
print queues for printers advertised on the network via IPP, DNS-SD, or the
legacy CUPS browsing protocol. It listens on UDP port 631.

When `cups-browsed` receives an IPP printer advertisement (even from an
untrusted source), it:
1. Fetches the advertised printer's IPP attributes.
2. Constructs a PPD file using Foomatic, potentially incorporating
   attacker-controlled data in the `FoomaticRIPCommandLine` attribute.
3. Registers a new local CUPS print queue backed by this PPD.

When any user subsequently prints to this queue, cupsd executes the
`FoomaticRIPCommandLine` command on the server, achieving RCE as the `lp` user.

The full attack chain (CVE-2024-47176 + CVE-2024-47076 + CVE-2024-47175 +
CVE-2024-47177) requires no authentication and is reachable from the local
network or internet if UDP 631 is exposed.

## Affected Service
- **Service:** cups-browsed (part of cups-filters)
- **Protocol:** UDP 631 (IPP browsing), and subsequently CUPS (TCP 631)
- **Vulnerable condition:** cups-browsed running with `BrowseRemoteProtocols` enabled
