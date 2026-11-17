# K8s No Resource Limits: Unbounded Pod Consumption (misconfig)

## Severity
**Medium** (CVSS 6.5)

## CVE / CWE
- CWE-770: Allocation of Resources Without Limits or Throttling

## Description
Pods deployed in the application namespace have no CPU or memory requests or
limits set. Without limits, a single runaway or malicious container can
consume all available node resources (CPU, memory), starving every other
workload on the node and causing cascading failures.

Without a LimitRange or ResourceQuota, the Kubernetes scheduler has no upper
bound to enforce, and the Linux kernel OOM killer arbitrarily terminates
processes when memory pressure becomes critical. This is a denial-of-service
risk that does not require any exploit: a bug or intentional loop in
application code is sufficient.

## Affected Service
- **Platform:** Kubernetes (k3s)
- **Missing controls:** LimitRange, ResourceQuota
