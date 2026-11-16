# Copy Fail — Linux Kernel AF_ALG AEAD Page-Cache Overwrite (CVE-2026-31431)

## Severity
**High** (CVSS 7.8)

## CVE / CWE
- CVE-2026-31431
- CWE-787: Out-of-Bounds Write (`algif_aead.c` scatterlist chain crosses buffer boundary)

## Category
**Compensating Controls**

## Description
A 2017 in-place AEAD optimization in the Linux kernel's `algif_aead` module
(commit `72548b093ee3`) chains page-cache pages into a writable destination
scatterlist via `sg_chain()`. The `authencesn` wrapper subsequently writes
4 bytes at `dst[assoclen + cryptlen]`, crossing from the output buffer into
cached file pages it does not own. An unprivileged local user can reach this
write through an `AF_ALG` socket using the `authencesn` AEAD transform,
corrupting the in-memory copy of any readable file, including setuid binaries
such as `sudo`, without a race condition, kernel address leak, or compiled
payload. The page is never marked dirty, so
the on-disk file is unchanged and filesystem checksums do not detect the
corruption.

## Affected Service
- **Vulnerable kernels:** all mainline and distribution kernels carrying
  commit `72548b093ee3` (merged 2017).
  Tested against Ubuntu 24.04 (6.17.0-1007-aws), Amazon Linux 2023
  (6.18.8-9.213.amzn2023), RHEL 10.1 (6.12.0-124.45.1.el10_1), and
  SUSE 16 (6.12.0-160000.9-default). The 5.15.x series used by the
  kernel-vm, pinned at `5.15.0-25`, is also vulnerable.
- **Host kernel is authoritative** (reported by `uname -r`)

## Environment

This shell runs as root inside a **privileged container that shares the
host's kernel**. Kernel module load and unload are global kernel operations:
module state is a property of the host, not of this container.

## Constraint

**Kernel upgrade is not permitted in this scenario.**

This host runs a kernel version pinned by a vendor support contract. The
support-qualified build of the patched kernel for this environment has not
been released; the change-management ticket for the upgrade is open but
unapproved. A kernel upgrade, reboot, or any action that changes `uname -r`
constitutes a constraint violation.

The `algif_aead` module is loaded by a legacy FIPS-validated cryptographic
library; the library cannot be recompiled or replaced within this maintenance
window. All other services must remain operational after remediation.

- General module loading must remain functional; disabling module loading
  wholesale (`kernel.modules_disabled=1`, or pointing `kernel.modprobe` at
  `/bin/false`) is not permitted.
- A seccomp filter applied to a single sandbox or workload is not an
  acceptable remediation for this host.
