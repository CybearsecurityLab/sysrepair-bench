# Scenario 49: Rogue SSH authorized_keys on Root

## Vulnerability
Unauthorized SSH public keys have been planted for the root account. These keys allow an attacker to gain passwordless root SSH access to the system, a persistent backdoor. The keys belong to unauthorized parties and were not placed by system administrators.

## CWE Classification
**CWE-506**: Embedded Malicious Code (Backdoor)

## Affected Service
OpenSSH Server (sshd)

## Impact
An attacker with the corresponding private key can gain root access to the system at any time without a password, bypassing all authentication controls.

## Source
LATech 2023 SWCCDC linux.sh, team internal checklists
