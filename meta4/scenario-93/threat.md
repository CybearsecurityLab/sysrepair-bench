# Jupyter Notebook — No Token Authentication (misconfig)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CWE-306: Missing Authentication for Critical Function

## Description
Jupyter Notebook, when started with `--NotebookApp.token=''` and no password
configured, disables all authentication. Any client that can reach port 8888 can
open the notebook interface, create and execute arbitrary Python code, browse the
filesystem, and read or write any file accessible to the notebook process — all
without providing any credentials.

This is a complete authentication bypass that grants full remote code execution
(RCE) to any network attacker. The impact is equivalent to an unauthenticated
interactive shell on the host. A single HTTP request to the API is sufficient to
confirm the exposure:

```
curl http://notebook-host:8888/api/contents
```

If this returns a file listing with HTTP 200, the server has no authentication.

## Affected Service
- **Service:** Jupyter Notebook (python-3.10 base)
- **Port:** 8888/TCP
- **Vulnerable configuration:** `--NotebookApp.token=''` with no password set

## Vulnerable Configuration
- `NotebookApp.token` set to empty string — disables token authentication
- `NotebookApp.password` not set — no password fallback
- Service bound to `0.0.0.0` — all interfaces exposed
