# Cgroup-Escape Capability (CAP_SYS_ADMIN) on a Helper Binary, CVE-2022-0492 / CWE-250

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-0492 (cgroup-v1 `release_agent` container escape via CAP_SYS_ADMIN)
- CWE-250: Execution with Unnecessary Privileges

## Description
CVE-2022-0492 lets an unprivileged process that holds **CAP_SYS_ADMIN** inside a
container escape to the host through the cgroup-v1 `release_agent` mechanism,
which the kernel runs **as root on the host**. The pivotal privilege is
`CAP_SYS_ADMIN`, the capability that authorizes `unshare(CLONE_NEWNS)` and
`mount(2)`.

In this scenario an unprivileged user obtains `CAP_SYS_ADMIN` through a **Linux
file capability** on a helper binary. The capability is stored in an extended
attribute and enforced by the kernel on every `execve(2)`. Any user who runs
the helper, including a fully unprivileged one, receives `CAP_SYS_ADMIN` in
that process's effective set and can perform privileged mounts (the exact
primitive CVE-2022-0492 turns into a host escape).

## Affected Service
- **Service:** a local helper binary carrying a Linux file capability
