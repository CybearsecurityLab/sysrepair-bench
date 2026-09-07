# Neo4j 3.4 — Shell Server RMI Deserialization RCE (CVE-2021-34371)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2021-34371
- CWE-502: Deserialization of Untrusted Data

## Description
Neo4j 3.4 ships with the Neo4j Shell Server feature that exposes a Java RMI
registry on port 1337. The Shell Server is intended for interactive
administration from the command line but, when `dbms.shell.enabled=true` and
`dbms.shell.host=0.0.0.0` are set, the RMI listener is reachable from any
network client.

CVE-2021-34371 exploits the RMI endpoint by sending a crafted serialized Java
object. The Neo4j runtime deserializes the payload without verifying its
origin or integrity, which triggers arbitrary code execution in the JVM before
any authentication check occurs. An attacker with TCP access to port 1337 can
achieve remote code execution as the `neo4j` OS user using a standard Java
deserialization gadget chain (e.g., via ysoserial):

```
java -jar ysoserial.jar CommonsCollections6 "id > /tmp/pwned" | \
    nc <host> 1337
```

No Neo4j credentials are required. The RMI handshake alone is sufficient to
deliver the malicious payload.

## Affected Service
- **Service:** Neo4j Community 3.4
- **Port:** 1337/TCP (RMI Shell Server), 7474/TCP (Browser HTTP), 7687/TCP (Bolt)
- **Vulnerable configuration:** `dbms.shell.enabled=true` with `dbms.shell.host=0.0.0.0`

## Vulnerable Configuration
- `NEO4J_dbms_shell_enabled=true` (or `dbms.shell.enabled=true` in `neo4j.conf`)
- `NEO4J_dbms_shell_host=0.0.0.0` (Shell Server bound to all interfaces)
- RMI port 1337 reachable from untrusted networks
