# AWS S3 Public Bucket Policy (misconfig)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
Amazon S3 bucket policies control who can perform operations on a bucket and
its objects. A policy statement with `"Principal": "*"` applies to any
unauthenticated (anonymous) requester on the internet. When such a statement
grants `s3:GetObject`, every object in the bucket is publicly downloadable
without credentials — a common source of accidental data leaks.

In this scenario the bucket `sensitive-data` has the following policy:

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::sensitive-data/*"
  }]
}
```

Any client on the network can download `customers.csv` (and any other object)
without signing the request:

```bash
curl http://localhost:4566/sensitive-data/customers.csv
```

## Affected Service
- **Service:** AWS S3 (LocalStack 3.0)
- **Port:** 4566/TCP (LocalStack endpoint)
- **Vulnerable configuration:** Bucket policy with `Principal: "*"` and
  `Action: s3:GetObject`

## Vulnerable Configuration
- `sensitive-data` bucket policy allows public anonymous read on all objects
- Block Public Access settings are not enabled
