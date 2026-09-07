# MinIO Public Bucket Anonymous Access (Misconfiguration)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- No CVE — misconfiguration
- CWE-284: Improper Access Control
- CWE-732: Incorrect Permission Assignment for Critical Resource

## Description
The MinIO object storage server has a bucket (`testbucket`) configured
with anonymous download access. Anyone who can reach the MinIO API on
port 9000 can download objects from the bucket without authentication,
including files containing secrets and credentials.

This mirrors the common S3 misconfiguration where bucket policies
allow `s3:GetObject` to `Principal: "*"`.

## Affected Service
- **Service:** MinIO object storage
- **Port:** 9000/TCP (API), 9001/TCP (console)
- **Bucket:** `testbucket`
- **Credentials:** `minioadmin` / `minioadmin`
