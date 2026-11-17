# SMB Signing Not Required (NTLM Relay Surface)

## Severity
**High** (CVSS 8.1 for the relay classes this enables)

## CVE / Reference
- No single CVE, this is a configuration-class weakness tracked by
  Microsoft advisory **ADV170014** and CIS Microsoft Windows Server Benchmark §2.3.8.x.
- Enables NTLM-relay primitives demonstrated by CVE-2019-1040 ("Drop the MIC"),
  CVE-2019-1166, and the broader `ntlmrelayx` / PetitPotam / PrinterBug chains.

## Description
The server neither requires nor enables SMB message signing, so it accepts and negotiates
SMB sessions without it. An attacker who
can coerce a client into authenticating to an attacker-controlled endpoint (LLMNR /
NBT-NS poisoning, PetitPotam, PrinterBug, WebDAV UNC) can then **relay** that NTLM
authentication to this server as a signed-session downgrade and execute commands as
the victim principal, including SCM, LDAP, or ADCS operations if the victim is
privileged.

Signing is a pure-server decision for the target: the client cannot force it if the
server does not require it.

## Affected Service
- **Service:** `LanmanServer`
- **Port:** 445/TCP
