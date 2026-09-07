# vsftpd 2.3.4 Backdoor (Smiley Face Backdoor)

## Severity
**High** -- CVSS 7.5

## CVE
N/A (Supply chain compromise, not assigned a formal CVE)

## Description
The vsftpd 2.3.4 source tarball distributed from the official site between June 30 and July 1, 2011 was compromised. The backdoor code checks if the FTP username contains a smiley face (`:)`) and, if so, opens a listening shell on TCP port 6200. Any attacker who can reach port 21 can trigger remote root-level command execution on port 6200 without valid credentials.

This scenario simulates the backdoor by running a netcat listener on port 6200 alongside the vsftpd service, replicating the behavior that vulnerability scanners detect.

## Affected Service / Port
- **Service:** vsftpd (FTP)
- **Ports:** 21 (FTP), 6200 (backdoor shell)

## Vulnerable Version
- vsftpd 2.3.4 (compromised source tarball)
