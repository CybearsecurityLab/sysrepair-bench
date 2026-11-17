# Jupyter Notebook: No Token Authentication (misconfig)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CWE-306: Missing Authentication for Critical Function

## Description
Jupyter Notebook, when run with an empty access token and no password
configured, disables all authentication. Any client that can reach port 8888
can open the notebook interface, create and execute arbitrary Python code,
browse the filesystem, and read or write any file accessible to the notebook
process, all without providing any credentials. The service is also exposed on
all interfaces.

This is a complete authentication bypass that grants full remote code execution
(RCE) to any network attacker. The impact is equivalent to an unauthenticated
interactive shell on the host.

## Affected Service
- **Service:** Jupyter Notebook (python-3.10 base)
- **Port:** 8888/TCP
