# UnrealIRCd 3.2 -- IRC Daemon Bound to 0.0.0.0

## Severity
**High** (CVSS 7.5) -- network exposure of a pinned legacy IRC daemon

## CVE / CWE
- CWE-668: Exposure of Resource to Wrong Sphere (bind to 0.0.0.0)
- Note: CVE-2010-2075 (UnrealIRCd backdoor) and CVE-2016-7144 (auth spoofing) are
  already covered by meta2/ scenarios. This scenario targets the network exposure
  surface only: the IRC daemon bound to all interfaces with no TLS gateway.

## Category
Compensating Control

## Constraint
**The UnrealIRCd version must not be changed.** Legacy IRC bots and scripts in the
environment depend on the specific version and protocol behaviour of the installed
Unreal3.2 build. The agent cannot upgrade, replace, or remove the daemon. The
compensating control is purely a network-layer measure. External clients must
retain access to the IRC service.

## Description
UnrealIRCd is configured to listen on `0.0.0.0:6667`, exposing the IRC daemon to
any host that can reach the machine. The daemon itself is a legacy/pinned version
with known vulnerabilities (covered in other scenarios). Binding it to all
interfaces unnecessarily increases the attack surface: any host can connect and
probe the daemon, attempt authentication bypasses, or exploit other CVEs.

## Affected Service
- **Service:** UnrealIRCd (Unreal3.2)
- **Port (vulnerable):** 6667/TCP on 0.0.0.0
- **Config:** /opt/unrealircd/Unreal3.2/unrealircd.conf

## Vulnerable Configuration
```
# unrealircd.conf (vulnerable)
listen {
    ip       *;
    port     6667;
    options { };
};
```
