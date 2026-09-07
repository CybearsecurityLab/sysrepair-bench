# K8s RBAC cluster-admin ServiceAccount (misconfig)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CWE-269: Improper Privilege Management

## Description
The ServiceAccount `superadmin` in the `default` namespace is bound directly
to the built-in `cluster-admin` ClusterRole via a ClusterRoleBinding. This
grants the service account — and any workload that mounts it — unrestricted
read, write, and delete access to every resource across every namespace in the
cluster, including Secrets, ConfigMaps, Pods, Nodes, and custom resources.

An attacker who can schedule a pod (or exec into an existing one) using this
service account can:

```bash
kubectl auth can-i '*' '*' --as=system:serviceaccount:default:superadmin
# → yes
```

This is equivalent to running as cluster root and bypasses all namespace-level
access boundaries.

## Affected Service
- **Platform:** Kubernetes (k3s)
- **Resource:** ClusterRoleBinding `superadmin-cluster-admin`
- **Vulnerable principal:** `system:serviceaccount:default:superadmin`

## Vulnerable Configuration
- ServiceAccount `superadmin` exists in namespace `default`
- ClusterRoleBinding binds it to `cluster-admin` (built-in super-admin role)
- No least-privilege scoping — any namespace, any resource, any verb
