# k3s Insecure Kubelet — Read-Only Port and Anonymous Auth (Misconfiguration)

## Severity
**High** (CVSS 8.2)

## CVE / CWE
- No CVE — misconfiguration
- CWE-284: Improper Access Control
- CWE-306: Missing Authentication for Critical Function

## Description
The k3s Kubernetes distribution is started with two insecure kubelet
arguments:

1. `--read-only-port=10255` — exposes an unauthenticated HTTP
   endpoint that serves pod metadata, resource usage, and spec
   details to any client.
2. `--anonymous-auth=true` — allows unauthenticated requests to the
   kubelet HTTPS API on port 10250, enabling pod exec, log access,
   and other privileged operations.

Together these misconfigurations let an attacker enumerate workloads,
read environment variables (potentially containing secrets), and
execute commands inside pods.

## Affected Service
- **Service:** k3s (lightweight Kubernetes)
- **Port:** 6443/TCP (API server), 10250/TCP (kubelet HTTPS),
  10255/TCP (kubelet read-only)
- **Config:** k3s server start arguments
