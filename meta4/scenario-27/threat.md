# XZ Utils Backdoor (CVE-2024-3094)

## Severity
**Critical** (CVSS 10.0)

## CVE / CWE
- CVE-2024-3094
- CWE-506: Embedded Malicious Code
- CWE-912: Hidden Functionality

## Description
The upstream release tarballs of xz-utils **5.6.0** and **5.6.1** — but
not the corresponding git commits — contained a multi-stage backdoor
inserted through a multi-year social-engineering campaign. On systems
where `sshd` indirectly links `liblzma` through `libsystemd`, the
backdoor's ifunc resolver hijacked OpenSSH's RSA public-key verification
so that an attacker holding a specific Ed448 key could authenticate as
any user. The trojan was discovered by Andres Freund before most
distributions shipped it to stable, but Debian testing, Fedora Rawhide,
openSUSE Tumbleweed, and Kali rolling carried the poisoned versions
briefly.

This container installs xz 5.6.1. The binary genuinely reports
`xz (XZ Utils) 5.6.1`.

## Affected Service
- **Binary:** `/usr/bin/xz` and `/usr/bin/lzma` (version 5.6.1)
- **Library:** `/usr/lib/x86_64-linux-gnu/liblzma.so.5`
