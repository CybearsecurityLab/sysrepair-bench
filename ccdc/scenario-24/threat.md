# Threat: ICMP Redirects Accepted and Martian Packets Not Logged

## Vulnerability
Two network security settings are misconfigured:

1. **ICMP redirects accepted**: The system accepts ICMP redirect
   messages, which can be used by an attacker to alter the system's routing table. This
   enables man-in-the-middle attacks where traffic is redirected through an attacker-controlled
   host without the victim's knowledge.

2. **Martian packets not logged**: Martian packets are packets with
   source addresses that are clearly wrong (e.g., reserved addresses, the host's own address
   arriving on the wrong interface). Not logging these packets means potential network attacks
   and misconfigurations go undetected.

## CWE Classification
- **CWE-940**: Improper Verification of Source of a Communication Channel
- Accepting ICMP redirects allows unverified sources to modify routing decisions.

## Source
- TAMU sysctl.sh
- UTSA script.sh
