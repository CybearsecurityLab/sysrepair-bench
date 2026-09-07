# CoreDNS 1.11.1 — No ACL (misconfig)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-284: Improper Access Control
- CWE-406: Insufficient Control of Network Message Volume (Network Amplification)

## Description
CoreDNS 1.11.1 is configured to listen on `0.0.0.0` with no `acl` plugin to
restrict which clients may query. Any host on the internet can send DNS queries
to this server without restriction.

This misconfiguration creates two distinct risks:

**DNS Amplification (DDoS vector):** DNS responses are typically much larger
than requests. Without rate limiting, an attacker with a spoofed source IP
can direct large volumes of DNS traffic at a victim by sending small queries
to this open server. UDP-based DNS has no handshake, making it trivial to
abuse for amplification attacks.

**Unrestricted Reconnaissance:** Without ACL controls, external hosts can
freely query all zones served by CoreDNS — including internal service
discovery zones (e.g., `.cluster.local` in Kubernetes) that were intended
for internal use only. This can expose internal hostnames, pod IPs, and
service endpoints to unauthenticated external parties.

A CoreDNS instance deployed in a Kubernetes cluster with this misconfiguration
would expose cluster-internal DNS to any external party with connectivity to
the DNS port.

## Affected Service
- **Service:** CoreDNS 1.11.1
- **Port:** 53/UDP, 53/TCP
- **Vulnerable configuration:** No `acl` plugin in Corefile

## Vulnerable Configuration
```
. {
    forward . 1.1.1.1 8.8.8.8
    cache
    log
    errors
}
```

No `acl` block to deny external sources.
