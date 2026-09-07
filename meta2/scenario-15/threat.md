# DistCC Unrestricted Access (Remote Code Execution)

## Severity
**High** | CVSS 9.3

## CVE
CVE-2004-2687

## Description
The DistCC (Distributed Compiler) daemon (`distccd`) is running without the `--allow` flag, which means it accepts connections from any remote host. DistCC is designed to distribute compilation jobs across a network, but when it accepts connections without IP-based access restrictions, it can be abused by an attacker to execute arbitrary commands on the server.

The vulnerability arises because the DistCC protocol allows the client to specify the compiler command to run. An attacker can send a crafted compilation request that executes arbitrary shell commands instead of a legitimate compiler invocation. This is a well-known attack vector documented in Metasploit as `exploit/unix/misc/distcc_exec`. The commands execute with the privileges of the `distccd` user, which may be sufficient for further privilege escalation.

## Affected Service
- **Service:** distccd (Distributed Compiler Daemon)
- **Port:** 3632/tcp
- **Protocol:** DistCC

## Vulnerable Configuration
The distccd daemon is started without the `--allow` flag:

```bash
distccd --daemon --no-detach --user distccd --port 3632 --log-stderr
```

Without `--allow`, distccd accepts connections from all IP addresses. An attacker can send a malicious compilation request to execute commands:

```
DIST00000001ARGC00000008ARGV00000002shARGV00000002-cARGV00000006whoamiARGV00000...
```
