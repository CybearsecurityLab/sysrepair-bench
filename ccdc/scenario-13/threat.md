# Scenario 13: PostgreSQL Trust Authentication for All Connections

## Vulnerability
PostgreSQL's host-based authentication is configured to use `trust` authentication for all connections (local and remote). This means any user can connect to any database without providing a password.

## CWE Classification
**CWE-284**: Improper Access Control

## Affected Service
PostgreSQL

## Impact
Any user on the network can connect to PostgreSQL as any user (including superuser) without authentication, allowing full database access.

## Source
Team internal checklists, general PostgreSQL hardening best practices
