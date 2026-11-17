# AWS IAM Policy Version Rollback (design flaw)

## Severity
**High** (CVSS 8.8)

## CVE / CWE
- CWE-269: Improper Privilege Management

## Description
AWS IAM managed policies support up to five versions. When a policy is updated,
the old versions are retained and can be reinstated by any principal that holds
the `iam:SetDefaultPolicyVersion` permission. If any older version is more
permissive than the current default, an attacker (or compromised account) can
silently escalate privileges simply by calling `SetDefaultPolicyVersion`: no
new resource creation, no CloudTrail alarm on unusual API calls.

In this scenario a managed policy retains a non-default version that grants
full administrator access, and an application user is allowed to change the
default policy version. That user can flip the default to the overpermissive
version and instantly gain administrator-equivalent access.

## Affected Service
- **Service:** AWS IAM (LocalStack 3.0)
- **Port:** 4566/TCP (LocalStack endpoint)
