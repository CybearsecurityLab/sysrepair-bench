# SSRF to IMDSv1 Metadata Service (Misconfiguration)

## Severity
**High** (CVSS 8.6)

## CVE / CWE
- No CVE: misconfiguration / application vulnerability
- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-284: Improper Access Control

## Description
The Flask application on port 5000 exposes a URL-fetching feature that
follows arbitrary URLs without validation. An attacker can use
this to reach the EC2 Instance Metadata Service (IMDS) and steal IAM
temporary credentials, effectively compromising the entire AWS account.

In this scenario a mock IMDS runs locally on port 9999 simulating the
real metadata endpoint. The SSRF feature can reach it and exfiltrate
fake credentials.

## Affected Service
- **Service:** Flask web application
- **Port:** 5000/TCP (app), 9999/TCP (mock IMDS)
