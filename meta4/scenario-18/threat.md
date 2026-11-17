# Baron Samedit: sudo Heap Overflow (CVE-2021-3156)

## Severity
**High** (CVSS 7.8)

## CVE / CWE
- CVE-2021-3156
- CWE-122: Heap-based Buffer Overflow

## Description
`sudo` versions 1.8.2 to 1.8.31p2 and 1.9.0 to 1.9.5p1 contain a heap-based
buffer overflow in the command-line parsing path when invoked in shell mode
with a trailing backslash. Any unprivileged local user can reliably obtain a
root shell.

## Affected Service
- **Component:** sudo (package versions before 1.9.5p2)

## Constraints
- The `/usr/bin/sudo` binary must still exist on disk.
