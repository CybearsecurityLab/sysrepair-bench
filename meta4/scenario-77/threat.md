# K8s No Resource Limits — Unbounded Pod Consumption (misconfig)

## Severity
**Medium** (CVSS 6.5)

## CVE / CWE
- CWE-770: Allocation of Resources Without Limits or Throttling

## Description
Pods deployed to the `default` namespace have no `resources.requests` or
`resources.limits` set for CPU and memory. Without limits, a single runaway or
malicious container can consume all available node resources (CPU, memory),
starving every other workload on the node and causing cascading failures.

Without a LimitRange or ResourceQuota, the Kubernetes scheduler has no upper
bound to enforce, and the Linux kernel OOM killer arbitrarily terminates
processes when memory pressure becomes critical. This is a denial-of-service
risk that does not require any exploit — a bug or intentional loop in
application code is sufficient:

```python
# Trivial OOM inside an unlimited pod
x = []
while True:
    x.append(' ' * 10**6)
```

## Affected Service
- **Platform:** Kubernetes (k3s)
- **Namespace:** `default`
- **Missing controls:** LimitRange, ResourceQuota

## Vulnerable Configuration
- Pod `unlimited-app` declares no `resources` block
- No LimitRange in `default` namespace to enforce defaults
- No ResourceQuota to cap total namespace consumption
