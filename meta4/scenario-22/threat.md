# Linux `nf_tables` Use-After-Free (CVE-2024-1086)

## Severity
**High** (CVSS 7.8)

## CVE / CWE
- CVE-2024-1086
- CWE-416: Use After Free

## Description
A use-after-free in the Linux kernel netfilter `nf_tables`
`nft_verdict_init()` path lets unprivileged local users with network
admin capability in their user namespace (the default on most desktop
distributions) reliably escalate to root. Public PoCs report >99%
reliability across kernels 5.14–6.6.

## Affected Service
- **Host kernel:** mainline fixed the flaw in 6.8-rc2, with stable
  backports to 5.15.149 / 6.1.76 / 6.6.15 / 6.7.3. Distributions
  backported `nf_tables` well below the 5.14 lower bound the PoC
  write-ups quote, so Ubuntu also ships fixes for 4.4, 4.15 and 5.4.
  The container shares the host kernel.

## Constraints
- This is a compensating-control scenario: the running kernel belongs to the
  host and cannot be upgraded, replaced, or masked from inside this system.
- The nftables userspace tooling (`nft`) must remain installed and functional.
