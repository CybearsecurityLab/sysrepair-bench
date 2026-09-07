# ActiveMQ 5.17.6 — Unauthenticated OpenWire port 61616 exposed

## Severity
**High** (network exposure of an unauthenticated broker transport)

## CVE / CWE
- CWE-284: Improper Access Control
- Context: CVE-2023-46604 (OpenWire deserialization RCE)

## IMPORTANT — scenario scope
The pinned image `apache/activemq-classic:5.17.6` already contains the fix for
CVE-2023-46604 (the OpenWire deserialization RCE was patched in 5.17.6, 5.16.7
and 5.15.16). The shipped binary is `activemq-broker-5.17.6.jar`, so that
specific RCE is **not** present in this image.

## Description
Apache ActiveMQ exposes the OpenWire wire protocol on port 61616. In the default
configuration this transport is reachable by any client on any network without
authentication. Even on a patched broker, an unauthenticated OpenWire endpoint
exposed to untrusted networks is a significant attack surface (message
injection/consumption, resource abuse, and exposure to any future protocol-level
vulnerability).

## Affected Service
- **Service:** Apache ActiveMQ Classic 5.17.6
- **Port:** 61616/TCP (OpenWire)
- **Residual risk:** unauthenticated OpenWire transport reachable from untrusted networks

## Vulnerable Configuration
- Port 61616 accessible from untrusted networks (no host firewall restriction)

## Constraints
- The ActiveMQ broker must stay running and its web console on port 8161 must
  remain reachable.
