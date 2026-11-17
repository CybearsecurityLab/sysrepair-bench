# Unquoted Service Path with Writable Parent Directory (Priv-Esc)

## Severity
**High** (CVSS 7.8, local privilege escalation to SYSTEM)

## CVE / Reference
- Configuration-class weakness, CWE-428 "Unquoted Search Path or Element".
- Microsoft guidance: KB article on service path quoting; routinely flagged by
  PowerUp, WinPEAS, Seatbelt, and OpenVAS's local-policy NVTs.
- Has been the enabling primitive behind dozens of vendor-specific CVEs (e.g.
  CVE-2021-24084-class service-installer bugs).

## Description
Windows Service Control Manager parses a service's executable path using
whitespace-delimited tokens when the path is not quoted, and probes each shorter
candidate (for example a binary named after the first word of a path containing spaces)
before the real executable.

If any earlier candidate exists **and** a non-admin principal can create it, that
principal wins: SCM launches the planted binary as `LocalSystem`. This image
compounds the issue by granting ordinary users modify rights on a directory in the
service's path, so an unprivileged user can drop a binary in a parent directory and
trigger a service restart (or wait for reboot) to gain SYSTEM.

## Affected Service
- **Service:** a Windows service registered with an unquoted executable path containing
  spaces, whose parent directory is writable by unprivileged users
