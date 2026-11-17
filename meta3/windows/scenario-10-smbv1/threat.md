# SMBv1 Protocol Enabled (EternalBlue Precondition)

## Severity
**Critical** (CVSS 9.3 for the underlying RCE class)

## CVE
- **CVE-2017-0144**, "EternalBlue" SMBv1 transactions RCE (and the rest of MS17-010:
  CVE-2017-0143/0145/0146/0147/0148).
- Independently of MS17-010, SMBv1 has accumulated downgrade and authentication
  weaknesses (CVE-2020-0796 "SMBGhost" affected SMBv3, but SMBv1 carries its own
  long-standing protocol-level issues that Microsoft no longer fixes).

## Description
The legacy SMBv1 dialect is **enabled** on this host. Modern Server Core builds default
to having SMBv1 off and the optional component uninstalled, turning it back on
re-exposes the surface that the WannaCry / NotPetya wave exploited via MS17-010. Even on
a fully patched kernel, keeping SMBv1 enabled:

- Allows unauthenticated downgrade negotiation from clients that should have moved to
  SMBv2/3 long ago.
- Bypasses signing and per-message integrity protections that newer dialects enforce
  by default.
- Triggers many compliance / OpenVAS findings (PCI-DSS, CIS Microsoft Windows Server
  Benchmark §3.x).

## Affected Service
- **Service:** `LanmanServer` (file/print sharing)
- **Port:** 445/TCP (SMB direct host)
