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

Additionally, an unscoped Lambda wildcard permission allows the role holder to
create or update Lambda functions and pass arbitrary roles, a well-known
privilege escalation path documented in multiple AWS security assessments.

In this scenario the execution role of a Lambda function has both of these
overbroad permissions and no permission boundary. An attacker with access to
this role can swap in an admin role and then invoke the function to execute
arbitrary code under it.

## Affected Service
- **Service:** AWS Lambda + IAM (LocalStack 3.0)
- **Port:** 4566/TCP (LocalStack endpoint)
