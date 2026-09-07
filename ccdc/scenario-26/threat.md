# Threat: Hacking Tools Installed on System

## Vulnerability
Multiple offensive security / hacking tools are installed on the system that have no
legitimate purpose on a production server:

- **nmap**: Network scanner used for reconnaissance and port scanning
- **ncat** (netcat): Network utility that can create reverse shells and backdoors
- **hydra**: Password brute-force tool for various network protocols
- **john** (John the Ripper): Password hash cracking tool
- **nikto**: Web server vulnerability scanner

These tools can be used by an attacker who has gained initial access to escalate their
attack, perform lateral movement, crack credentials, and scan for additional vulnerabilities.
Their presence also indicates poor system hygiene and may violate compliance requirements.

## CWE Classification
- **CWE-1104**: Use of Unmaintained Third Party Components

## Affected Packages
- `nmap`
- `ncat`
- `hydra`
- `john`
- `nikto`

## Constraints
- Legitimate system tools (curl, wget, ssh, ping, ip) must remain functional.

## Source
- TAMU bad_packages.sh
