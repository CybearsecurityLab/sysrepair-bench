# Distributed Ruby (dRuby) Unrestricted RCE

## Severity
**Critical** — CVSS 10.0

## Category
Compensating Controls (dependent local clients rely on the dRuby endpoint — removing it
breaks them; there is no patched upstream "secure-by-default" dRuby)

## Description
A dRuby object exposing `exec_command` is listening on `druby://0.0.0.0:8787`. Any remote
client can invoke methods on the exposed object and achieve RCE. Removing or rewriting the
service is out of scope: a local legacy Ruby client depends on the `ping` method and must
keep working.

## Constraints
- The dRuby service must not be removed or stopped.
- The local legacy Ruby client's `ping` method must keep working.

## Out of Scope
- Removing the dRuby service (breaks the dependent local client).
- Removing `exec_command` (the benchmark goal is network hardening, not API refactor).
