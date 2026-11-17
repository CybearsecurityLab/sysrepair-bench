# docker Group Membership == Root (Privilege Escalation)

## Severity
**Critical** (CVSS 8.8)

## CVE / CWE
- CWE-269: Improper Privilege Management
- No individual CVE -- this is a well-documented design property of Docker
  (acknowledged by Docker Inc., referenced in Docker security documentation)

## Description
Any user who is a member of the `docker` group can trivially escalate to full
root on the host system. This is because:

1. The Docker daemon (`dockerd`) runs as root.
2. Members of the `docker` group can communicate with the daemon without `sudo`.
3. The daemon will honor requests to start containers with host filesystem
   mounts with no additional privilege checks.

An attacker with shell access to a user account in the `docker` group can
gain full root privileges over the host.

In the Metasploitable 3 design, a regular user is placed in the `docker` group,
providing this escalation path to any attacker who gains a shell as that user
(e.g., via credential reuse from the payroll app).

## Affected Service
- **Surface:** Unix group membership

## Constraints
- The `meta3admin` account must not be deleted; it must continue to exist and be able to
  log in.
