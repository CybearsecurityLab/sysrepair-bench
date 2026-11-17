# K8s NodePort Exposure: Internal Service Exposed Externally (misconfig)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-668: Exposure of Resource to Wrong Sphere

## Description
An internal Kubernetes Service is exposed as a NodePort, binding a high port on
every node's external network interface. This makes the service reachable from
any host that can reach the node, including external networks, even though it
is an internal application that should only be accessible within the cluster.

NodePort services bypass ClusterIP's cluster-internal restriction and expose
the backend pod directly on a high port of every node.

Services that should be internal (databases, admin interfaces, metrics
endpoints) are inadvertently made publicly accessible whenever NodePort is
used without an accompanying network-level firewall rule.

## Affected Service
- **Platform:** Kubernetes (k3s)
- **Exposed port:** TCP 30080 on all node IPs
