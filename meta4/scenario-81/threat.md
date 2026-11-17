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
as plaintext `String` parameters. Any IAM principal with `ssm:GetParameter` (a
broadly granted permission) can retrieve the raw secret value with a single
CLI call.

The secret also appears verbatim in CloudTrail `GetParameter` response data,
SDK debug logs, and any monitoring tool that captures SSM API responses.

## Affected Service
- **Service:** AWS SSM Parameter Store (LocalStack 3.0)
- **Port:** 4566/TCP (LocalStack endpoint)
