# K8s No NetworkPolicy: Flat Networking (misconfig)

## Severity
**High** (CVSS 8.1)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
Kubernetes does not enforce any pod-to-pod traffic restrictions unless
NetworkPolicy objects are explicitly applied. With no NetworkPolicy applied to
a sensitive namespace, any pod anywhere in the cluster, including potentially
compromised workloads in other namespaces, can send traffic directly to pods in
that namespace on any port.

This violates the principle of least privilege at the network layer: a
compromised frontend pod in one namespace can freely probe and attack backend
services in another as if they were on the same flat network.

## Affected Service
- **Platform:** Kubernetes (k3s)
- **Missing control:** no NetworkPolicy applied to the backend namespace
