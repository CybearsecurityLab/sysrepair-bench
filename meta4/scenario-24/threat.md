# BuildKit Build-Time Container Escape (CVE-2024-23651)

## Severity
**High** (CVSS 8.7)

## CVE / CWE
- CVE-2024-23651
- CWE-362: Concurrent Execution (Race Condition)

## Description
BuildKit ≤ 0.12.4's handling of `RUN --mount=type=cache` is racy: a
malicious Dockerfile can swap the cache-mount target for a symlink that
points outside the build sandbox between the time BuildKit prepares the
mount and the time the `RUN` step executes. The executed command then
operates on host paths, enabling arbitrary host-file read/write during
an otherwise "untrusted" image build — the canonical "CI pipeline
building an attacker-submitted Dockerfile" compromise.

## Affected Service
- **Binary:** `/usr/bin/buildkitd` (or `/usr/local/bin/buildkitd`) at
  version 0.12.4 or earlier
- **Exposure surface:** CI builds of untrusted Dockerfiles
