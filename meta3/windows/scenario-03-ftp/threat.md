# IIS FTP, Anonymous Authentication with Read+Write Authorization

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness, CWE-284 improper access control, CWE-287 weak authN)

## Description
The IIS FTP site on port 21 accepts **anonymous** logins and its authorization
grants anonymous users **Read and Write** permissions. An unauthenticated attacker
reaching TCP/21 can:

- List and download every file under the FTP root.
- Upload arbitrary content, useful for staging tooling on the host or for pivoting:
  if the FTP root happens to overlap with an IIS web root, uploaded files become
  directly reachable over HTTP.

Authentication is further weakened by basic authentication being disabled, meaning the
anonymous path is the only authentication path.

This reproduces the configuration shipped by upstream Metasploitable3.

## Affected Service
- **Service:** `ftpsvc` (IIS FTP Service)
- **Port:** 21/TCP (control), 50000-50050/TCP (passive data)
