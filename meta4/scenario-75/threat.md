# K8s RBAC cluster-admin ServiceAccount (misconfig)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CWE-269: Improper Privilege Management

## Description
A ServiceAccount is bound directly to the built-in `cluster-admin` ClusterRole
via a ClusterRoleBinding. This grants the service account, and any workload
that mounts it, unrestricted read, write, and delete access to every resource
across every namespace in the cluster, including Secrets, ConfigMaps, Pods,
Nodes, and custom resources.

An attacker who can schedule a pod (or exec into an existing one) using this
service account is equivalent to running as cluster root and bypasses all
namespace-level access boundaries.

## Affected Service
- **Platform:** Kubernetes (k3s)
