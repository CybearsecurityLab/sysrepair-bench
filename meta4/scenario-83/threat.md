# AWS SNS Open Topic (misconfig)

## Severity
**Medium** (CVSS 5.3)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
Amazon SNS topic access policies control who can publish, subscribe, and
manage a topic. When the `SNS:Subscribe` action is granted to
`"Principal": "*"`, any AWS account or unauthenticated principal can
subscribe an endpoint (SQS queue, HTTP URL, email, Lambda) to the topic
and receive every message published to it.

The topic `app-debug-events` publishes internal application diagnostics
including request traces, stack traces, and environment metadata. Its
current policy contains:

```json
{
  "Sid": "OpenSubscribe",
  "Effect": "Allow",
  "Principal": "*",
  "Action": "SNS:Subscribe",
  "Resource": "<topic-arn>"
}
```

An attacker who subscribes a controlled endpoint receives a real-time stream
of debug data, potentially exposing credentials, internal IP addresses, and
application logic.

## Affected Service
- **Service:** AWS SNS (LocalStack 3.0)
- **Port:** 4566/TCP (LocalStack endpoint)
- **Vulnerable configuration:** `SNS:Subscribe` granted to `Principal: "*"`

## Vulnerable Configuration
- Topic policy `OpenSubscribe` statement allows any principal to subscribe
- Publish is correctly scoped to the account root, but Subscribe is open
