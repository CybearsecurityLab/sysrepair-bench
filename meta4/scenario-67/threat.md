# BACnet/IP — Unauthenticated Building Automation Access (protocol design flaw)

## Severity
**High** (CVSS 8.6)

## CVE / CWE
- CWE-306: Missing Authentication for Critical Function

## Category
Compensating Controls

## Description
BACnet (Building Automation and Control Networks) is an ASHRAE/ISO/ANSI
standard protocol for building automation systems — HVAC, lighting, access
control, fire detection. The standard UDP port is 47808 (0xBAC0).

BACnet has **no native authentication or encryption** by design. Any host that
can send UDP packets to port 47808 can:
- Enumerate all building automation devices (Who-Is broadcast)
- Read any object property: temperature setpoints, door states, alarm statuses
- Write properties to manipulate HVAC setpoints, unlock doors, disable fire alarms
- Send Out-of-Service commands to bypass sensor readings

A 2013 Project Basecamp study found over 25,000 BACnet devices directly
internet-accessible. When exposed on `0.0.0.0`, the BACnet server accepts
requests from any source without authentication or authorization checks.

## Affected Service
- **Service:** BACnet/IP server (simulated)
- **Port:** 47808/UDP
- **Vulnerable configuration:** server bound to `0.0.0.0` with no firewall

## Constraints
- The BACnet device must remain running and must keep answering Who-Is
  requests with an I-Am reply from loopback.
