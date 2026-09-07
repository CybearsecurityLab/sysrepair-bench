# Cgroup-Escape Capability (CAP_SYS_ADMIN) on a Helper Binary — CVE-2022-0492 / CWE-250

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-0492 (cgroup-v1 `release_agent` container escape via CAP_SYS_ADMIN)
- CWE-250: Execution with Unnecessary Privileges

## Description
CVE-2022-0492 lets an unprivileged process that holds **CAP_SYS_ADMIN** inside a
container escape to the host: it mounts a cgroup-v1 controller, enables
`notify_on_release`, writes a payload path to `release_agent`, and triggers it —
the kernel runs the payload **as root on the host**. The pivotal privilege is
`CAP_SYS_ADMIN`, the capability that authorizes `unshare(CLONE_NEWNS)` and
`mount(2)`.

In this scenario an unprivileged user obtains `CAP_SYS_ADMIN` through a **Linux
file capability**. The helper `/usr/local/bin/caphelper` carries
`cap_sys_admin+ep`, stored in its `security.capability` extended attribute and
enforced by the kernel on every `execve(2)`. Any user who runs it — including a
fully unprivileged one — receives `CAP_SYS_ADMIN` in that process's effective
set and can perform privileged mounts (the exact primitive CVE-2022-0492 turns
into a host escape). The helper prints `PRIVOP_OK` only when the privileged mount
actually succeeds, proving the capability is live and abusable by a non-root
user.

## Affected Service
- **Binary:** `/usr/local/bin/caphelper` (`cap_sys_admin+ep` file capability)
- **Kernel bit:** CAP_SYS_ADMIN = bit 21

## Vulnerable Configuration
- `setcap cap_sys_admin+ep /usr/local/bin/caphelper` on a world-executable binary
- An unprivileged user (`appuser`) can exec it to perform a CAP_SYS_ADMIN mount
