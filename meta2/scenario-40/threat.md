# VNC Exposed on All Interfaces

## Severity
**High** — CVSS 9.0 (weak/guessable password, cleartext transport)

## Category
Compensating Controls (administrative VNC access must remain available to remote admins,
but direct exposure to untrusted networks must be eliminated)

## Description
The VNC server listens on `0.0.0.0:5900` with a short password and no transport encryption.
A full fix (kill VNC, replace with RDP-over-TLS) is out of scope for this host.

## Constraints
- Administrative VNC access must remain available to remote admins; the VNC service must
  not be killed or replaced with another remote-desktop stack.
- sshd on port 22 must remain running.

## Out of Scope
- Replacing VNC with another remote-desktop stack.
- Raising VNC password strength / adding TLS (separate scenarios S08/S09 cover auth).
