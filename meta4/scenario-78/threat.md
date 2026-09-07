# K8s NodePort Exposure — Internal Service Exposed Externally (misconfig)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-668: Exposure of Resource to Wrong Sphere

## Description
The Kubernetes Service `internal-svc` is configured with `type: NodePort`,
binding port 30080 on every node's external network interface. This makes the
service reachable from any host that can reach the node — including external
networks — even though it is an internal application that should only be
accessible within the cluster.

NodePort services bypass ClusterIP's cluster-internal restriction and expose
the backend pod directly on a high port of every node:

```bash
# Reachable from outside the cluster (no credentials needed):
curl http://<node-ip>:30080
```

Services that should be internal (databases, admin interfaces, metrics
endpoints) are inadvertently made publicly accessible whenever NodePort is
used without an accompanying network-level firewall rule.

## Affected Service
- **Platform:** Kubernetes (k3s)
- **Resource:** Service `internal-svc` in namespace `default`
- **Exposed port:** TCP 30080 on all node IPs

## Vulnerable Configuration
- `spec.type: NodePort` on an internal-only service
- NodePort 30080 bound on `0.0.0.0` of every cluster node
- No firewall or NetworkPolicy restricting external access to the NodePort range
