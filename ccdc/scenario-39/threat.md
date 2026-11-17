# Scenario 39: Shadow Password File World-Readable

## Vulnerability
The system password hash file is world-readable, exposing password hashes to all users on the system. Any user can read the file and attempt offline password cracking.

## CWE Classification
**CWE-732**: Incorrect Permission Assignment for Critical Resource

## Affected Service
System authentication files

## Impact
Any local user can read password hashes and perform offline brute-force cracking to obtain other users' passwords, including root.

## Source
LATech 2023 SWCCDC linux.sh, TAMU CCDC team checklists
