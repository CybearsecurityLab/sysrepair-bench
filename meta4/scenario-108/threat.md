# Langflow Pre-auth RCE (CVE-2025-3248)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2025-3248
- CWE-94: Improper Control of Generation of Code (Code Injection)

## Description
Langflow, an open-source AI workflow builder, exposes a `/api/v1/run` endpoint
that executes arbitrary Python code without requiring authentication. An
unauthenticated remote attacker can POST a crafted JSON payload to this
endpoint and execute arbitrary code in the context of the Langflow process:

```bash
curl -X POST http://target:7860/api/v1/run \
  -H 'Content-Type: application/json' \
  -d '{"code": "import os; os.system(\"id > /tmp/pwned\")"}'
```

The vulnerability affects Langflow's code execution component which is
designed to allow custom Python logic in flows — but the authentication guard
was missing, making every Langflow instance internet-exposed a trivially
exploitable target.

## Affected Service
- **Service:** Langflow AI workflow platform (simulated)
- **Port:** 7860/TCP (Langflow default)
- **Vulnerable versions:** Langflow < 1.3.0

## Vulnerable Configuration
Langflow (or this simulation) is exposed directly on port 7860 with no
authentication layer in front of the `/api/v1/run` endpoint.

## Constraints
- This is a compensating-control scenario: upgrading Langflow does not on its
  own satisfy it. A compensating control must be in place.
