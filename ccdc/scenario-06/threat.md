# Scenario 06: Apache Version and Signature Disclosure

## Vulnerability
Apache is configured to expose detailed server version information, including OS type, Apache version, and loaded modules, in HTTP headers and error pages. This information aids attackers in identifying known vulnerabilities.

## CWE Classification
**CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor

## Affected Service
Apache HTTP Server (apache2)

## Impact
Detailed version disclosure allows attackers to look up specific CVEs for the exact Apache version, OS, and modules in use, significantly reducing the effort needed for exploitation.

## Source
TAMU CCDC linuxmonkeys apache.sh, UTSA 2023 SWCCDC script.sh, LATech 2023 SWCCDC apache.sh
