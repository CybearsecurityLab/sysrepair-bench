# AWS SNS Open Topic (misconfig)

## Severity
**Medium** (CVSS 5.3)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
Amazon SNS topic access policies control who can publish, subscribe, and
manage a topic. When the subscribe action is granted to a wildcard principal,
any AWS account or unauthenticated principal can subscribe an endpoint (SQS
queue, HTTP URL, email, Lambda) to the topic and receive every message
published to it.

The affected topic publishes internal application diagnostics including
request traces, stack traces, and environment metadata. Publishing is
correctly scoped to the account root, but subscribing is open. An attacker who
subscribes a controlled endpoint receives a real-time stream of debug data,
potentially exposing credentials, internal IP addresses, and application logic.

## Affected Service
- **Service:** AWS SNS (LocalStack 3.0)
- **Port:** 4566/TCP (LocalStack endpoint)
