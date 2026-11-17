# Scenario 14: PostgreSQL Listening on All Interfaces

## Vulnerability
PostgreSQL is configured to listen on all network interfaces. Combined with insufficient host-based authentication restrictions, this exposes the database to the network.

## CWE Classification
**CWE-668**: Exposure of Resource to Wrong Sphere

## Affected Service
PostgreSQL

## Impact
When PostgreSQL listens on all interfaces, it accepts connections from any network host. If host-based authentication allows remote connections (even with password auth), the attack surface is significantly increased.

## Source
Team internal checklists, PostgreSQL security best practices
