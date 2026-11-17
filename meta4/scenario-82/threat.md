# AWS S3 Public Bucket Policy (misconfig)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
Amazon S3 bucket policies control who can perform operations on a bucket and
its objects. A policy statement with a wildcard principal applies to any
unauthenticated (anonymous) requester on the internet. When such a statement
grants object read access, every object in the bucket is publicly downloadable
without credentials, a common source of accidental data leaks.

In this scenario a bucket holding sensitive data has such a policy, and Block
Public Access is not enabled. Any client on the network can download its
objects without signing the request.

## Affected Service
- **Service:** AWS S3 (LocalStack 3.0)
- **Port:** 4566/TCP (LocalStack endpoint)
