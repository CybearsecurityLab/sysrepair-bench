# PwnKit: polkit pkexec LPE (CVE-2021-4034)

## Severity
**High** (CVSS 7.8)

## CVE / CWE
- CVE-2021-4034
- CWE-787: Out-of-bounds Write (argv[0] = NULL mishandling)

## Description
The setuid-root pkexec binary (polkit up to 0.120) mishandles the case where
`argv[0]` is NULL. The argument parsing loop reads past the end of `argv` into
`envp`, allowing an unprivileged local user to introduce an attacker-controlled
environment variable into the re-exec'd process and load a malicious shared
library as root.

Public PoCs reliably yield a root shell in under a second on any
vulnerable system.

## Affected Service
- **Component:** polkit pkexec (policykit-1 before 0.105-26ubuntu1.2 on
  Ubuntu 20.04, or upstream polkit up to 0.120)

## Constraints
- The `/usr/bin/pkexec` binary must still exist on disk.
