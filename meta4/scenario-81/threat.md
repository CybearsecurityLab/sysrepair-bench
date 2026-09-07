# AWS SSM Plaintext Parameters (misconfig)

## Severity
**Medium** (CVSS 6.5)

## CVE / CWE
- CWE-312: Cleartext Storage of Sensitive Information

## Description
AWS Systems Manager (SSM) Parameter Store supports three parameter types:
`String`, `StringList`, and `SecureString`. Only `SecureString` encrypts the
value at rest using AWS KMS. Parameters stored as type `String` are kept in
plaintext and returned unredacted in every `GetParameter` API response.

In this scenario the application stores database credentials and an API key
as `String` parameters:

- `/app/db-password` — type `String`
- `/app/api-key` — type `String`

Any IAM principal with `ssm:GetParameter` (a broadly granted permission) can
retrieve the raw secret value with a single CLI call:

```bash
awslocal ssm get-parameter --name /app/db-password --query 'Parameter.Value'
```

The secret also appears verbatim in CloudTrail `GetParameter` response data,
SDK debug logs, and any monitoring tool that captures SSM API responses.

## Affected Service
- **Service:** AWS SSM Parameter Store (LocalStack 3.0)
- **Port:** 4566/TCP (LocalStack endpoint)
- **Vulnerable configuration:** Parameters created with `--type String`

## Vulnerable Configuration
- `/app/db-password` and `/app/api-key` stored as `Type: String` (plaintext)
- No KMS key association; secrets visible to any `ssm:GetParameter` caller
