# AWS Lambda Privilege Escalation (design flaw)

## Severity
**High** (CVSS 8.8)

## CVE / CWE
- CWE-269: Improper Privilege Management

## Description
AWS Lambda functions execute under an IAM execution role. When that role
includes `iam:PassRole` without a resource condition, any principal that can
update the function's configuration (e.g., `lambda:UpdateFunctionConfiguration`)
can swap the execution role for an admin role and gain administrator-equivalent
access on the next invocation.

Additionally, `lambda:*` without scope allows the role holder to create or
update Lambda functions and pass arbitrary roles — a well-known privilege
escalation path documented in multiple AWS security assessments.

The role `lambda-exec-role` attached to `app-processor` contains:

```json
{
  "Statement": [
    {"Action": "lambda:*",    "Effect": "Allow", "Resource": "*"},
    {"Action": "iam:PassRole","Effect": "Allow", "Resource": "*"}
  ]
}
```

An attacker with access to this role can call:

```bash
awslocal lambda update-function-configuration \
  --function-name app-processor \
  --role arn:aws:iam::000000000000:role/AdminRole
```

and then invoke the function to execute arbitrary code under the admin role.

## Affected Service
- **Service:** AWS Lambda + IAM (LocalStack 3.0)
- **Port:** 4566/TCP (LocalStack endpoint)
- **Vulnerable configuration:** `iam:PassRole` on `Resource: "*"` with no
  condition; `lambda:*` on all resources

## Vulnerable Configuration
- `lambda-exec-role` inline policy grants `iam:PassRole` on `"Resource": "*"`
- No permission boundary on the role to cap maximum privilege
