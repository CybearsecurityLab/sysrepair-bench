# Looney Tunables — glibc `GLIBC_TUNABLES` Buffer Overflow (CVE-2023-4911)

## Severity
**High** (CVSS 7.8)

## CVE / CWE
- CVE-2023-4911
- CWE-122: Heap-based Buffer Overflow

## Description
glibc 2.34 through 2.37 contain a buffer overflow in the dynamic loader's
processing of the `GLIBC_TUNABLES` environment variable. The
`parse_tunables` function fails to stop copying when the tunable string
contains a malformed `tunable=tunable=value` sequence, writing past the
end of the `tunestr` buffer. Combined with a SUID binary (any — e.g.
`/usr/bin/su`), an unprivileged local user reliably obtains a root shell.

## Affected Service
- **Library:** `glibc` / `libc6` 2.34–2.37
- On Ubuntu 22.04: `libc6 < 2.35-0ubuntu3.4`
