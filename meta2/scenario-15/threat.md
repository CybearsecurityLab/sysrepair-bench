# DistCC Unrestricted Access (Remote Code Execution)

## Severity
**High** | CVSS 9.3

## CVE
CVE-2004-2687

## Description
The DistCC (Distributed Compiler) daemon (`distccd`) has no IP-based access restriction configured, which means it accepts connections from any remote host. DistCC is designed to distribute compilation jobs across a network, but when it accepts connections without IP-based access restrictions, it can be abused by an attacker to execute arbitrary commands on the server.

The vulnerability arises because the DistCC protocol allows the client to specify the compiler command to run. A compilation request can therefore name arbitrary shell commands instead of a legitimate compiler invocation. The commands execute with the privileges of the `distccd` user, which may be sufficient for further privilege escalation.

## Affected Service
- **Service:** distccd (Distributed Compiler Daemon)
- **Port:** 3632/tcp
- **Protocol:** DistCC
