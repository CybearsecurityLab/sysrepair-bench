# Prometheus 2.40.0: Unauthenticated Metrics Endpoint (misconfig)

## Severity
**Medium** (CVSS 5.3)

## CVE / CWE
- CWE-306: Missing Authentication for Critical Function

## Description
Prometheus 2.40.0, when started without a web configuration file, exposes all
HTTP endpoints, including the metrics and targets APIs, without requiring any
authentication. Any client that can reach port 9090 can retrieve a full
inventory of monitored targets, job names, label sets, and internal Prometheus
performance metrics. This leaks the complete infrastructure topology:
hostnames, IP addresses, service names, and the scrape configuration of every
monitored system.

An attacker can silently enumerate the entire monitored estate with a single
request.

This represents a significant reconnaissance advantage and can facilitate more
targeted follow-on attacks against exposed services.

## Affected Service
- **Service:** Prometheus 2.40.0
- **Port:** 9090/TCP
