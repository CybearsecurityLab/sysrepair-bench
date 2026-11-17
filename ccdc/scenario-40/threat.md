# Scenario 40: Account Database Writable by Others

## Vulnerability
The system account database file is world-writable, allowing any user to modify it. An attacker can add new users, change UIDs to 0 (root), or modify shell assignments to gain unauthorized access.

## CWE Classification
**CWE-732**: Incorrect Permission Assignment for Critical Resource

## Affected Service
System authentication files

## Impact
Any local user can add a UID 0 account, change their shell, or modify other users' entries. This is a trivial privilege escalation path.

## Source
LATech 2023 SWCCDC linux.sh
