# Neo4j 3.4: Shell Server RMI Deserialization RCE (CVE-2021-34371)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2021-34371
- CWE-502: Deserialization of Untrusted Data

## Description
Neo4j 3.4 ships with the Neo4j Shell Server feature that exposes a Java RMI
registry on port 1337. The Shell Server is intended for interactive
administration from the command line but, when enabled and bound to all
interfaces, the RMI listener is reachable from any network client.

CVE-2021-34371 exploits the RMI endpoint by sending a crafted serialized Java
object. The Neo4j runtime deserializes the payload without verifying its
origin or integrity, which triggers arbitrary code execution in the JVM before
any authentication check occurs. An attacker with TCP access to port 1337 can
achieve remote code execution as the Neo4j OS user.

No Neo4j credentials are required. The RMI handshake alone is sufficient to
deliver the malicious payload.

## Affected Service
- **Service:** Neo4j Community 3.4
- **Port:** 1337/TCP (RMI Shell Server), 7474/TCP (Browser HTTP), 7687/TCP (Bolt)
