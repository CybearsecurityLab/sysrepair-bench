# BuildKit Arbitrary Host-File Delete/Replace (CVE-2024-23652)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CVE-2024-23652
- CWE-59: Improper Link Resolution Before File Access (symlink)

## Description
During teardown of a cache or bind mount in a `RUN` step, BuildKit up to
0.12.4 followed symlinks that the build process itself had planted inside the
mount target. An attacker-submitted Dockerfile can therefore cause BuildKit to
delete or rename arbitrary host files owned by the BuildKit daemon user when
the `RUN` step completes, disrupting the host or replacing binaries used by
subsequent CI jobs.

## Affected Service
- **Component:** buildkitd / buildctl up to 0.12.4
