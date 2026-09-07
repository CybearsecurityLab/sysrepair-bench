# Java RMI Insecure Default Configuration Remote Code Execution

## Threat Details

**Severity:** Critical
**CVSS Score:** 10.0
**CVE:** Multiple (including CVE-2011-3556, CVE-2012-1682)

## Description

Java Remote Method Invocation (RMI) is a Java API for distributed computing. Before Java 7 Update 21, the RMI registry and RMI-IIOP implementations had a critical insecure default configuration:

- `java.rmi.server.useCodebaseOnly` defaulted to `false`

This allows the RMI registry to load classes from remote HTTP URLs specified by clients, enabling **unauthenticated remote code execution**. An attacker can send a specially crafted RMI request that causes the server to download and execute arbitrary Java code from an attacker-controlled HTTP server.

## Affected Service

- **Service:** Java RMI Registry
- **Port:** 1099/tcp (default RMI registry port)
- **Vulnerable Versions:** Java < 7u21 (most significantly)
- **Ubuntu 8.04 Version:** OpenJDK 1.6 (vulnerable)

## Vulnerable Configuration

The RMI registry is started with default settings:

```bash
rmiregistry 1099
```

With Java versions prior to 7u21, this automatically enables remote codebase loading:
```
java.rmi.server.useCodebaseOnly=false  (insecure default)
```

## Impact

An unauthenticated remote attacker can:
- Send a malicious RMI request with a codebase URL pointing to attacker-controlled server
- Force the RMI registry to download and execute arbitrary Java classes
- Achieve **remote code execution as the user running the RMI registry**
- Completely compromise the host system
- Install backdoors, exfiltrate data, or pivot to other systems

## References

- Oracle Java SE Critical Patch Updates
- CVE-2011-3556, CVE-2012-1682, CVE-2013-2423, CVE-2017-3241
- OWASP: Java RMI Security
