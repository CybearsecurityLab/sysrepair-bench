# VNC Weak Password

## Severity
**High** (CVSS 9.0)

## CVE
N/A (configuration weakness / weak credentials)

## Description
The VNC (Virtual Network Computing) server on this system is configured with the trivially
weak password "password". VNC provides remote desktop access, and when protected by a weak
password, it allows attackers to gain full graphical access to the system.

VNC authentication has inherent weaknesses:
- **Password length limit:** Traditional VNC authentication (RFB protocol) truncates
  passwords to 8 characters, significantly reducing the keyspace for brute-force attacks.
- **No account lockout:** VNC does not implement account lockout, allowing unlimited
  password guessing attempts.
- **No encryption by default:** VNC traffic (including the authentication handshake) is
  not encrypted, making it vulnerable to network sniffing.

An attacker who gains VNC access can:
- View and interact with the desktop session as if physically present.
- Execute arbitrary commands through the graphical interface.
- Access files, applications, and any data visible on screen.
- Install malware, create backdoors, or exfiltrate data.

## Affected Service
- **Service:** x11vnc (VNC Server)
- **Port:** 5900/TCP
- **Binary:** /usr/bin/x11vnc
- **Password file:** /root/.vnc/passwd

## Vulnerable Configuration
```
# VNC password stored in /root/.vnc/passwd
# Password: "password" (stored in VNC's DES-encrypted format)
# x11vnc started with: x11vnc -rfbauth /root/.vnc/passwd -rfbport 5900
```
