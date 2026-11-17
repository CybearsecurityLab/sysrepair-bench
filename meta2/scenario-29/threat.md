# Distributed Ruby (DRb) Unrestricted Remote Code Execution

## Severity
**High** (CVSS 10.0)

## CVE
N/A (insecure service configuration)

## Description
A Distributed Ruby (DRb/dRuby) service is running on this system, listening on all
network interfaces on port 8787 without any Access Control List (ACL)
restrictions. DRb is Ruby's native distributed object system that allows Ruby programs to
communicate over a network. When exposed without authentication or ACL restrictions, any
remote host can connect to the service and invoke methods on the exposed Ruby objects.

The DRb service on this system exposes an object with methods that allow:
- Arbitrary command execution
- Arbitrary file reading

This effectively grants unauthenticated remote code execution (RCE) with the privileges
of the Ruby process (typically root in this container). An attacker can execute any system
command, read any file, install backdoors, or pivot to other systems.

## Affected Service
- **Service:** DRb (Distributed Ruby) Service
- **Port:** 8787/TCP
