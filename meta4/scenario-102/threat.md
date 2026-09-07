# Zabbix 5.0 — Default Credentials + API RCE (CVE-2022-23131)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2022-23131 (SAML SSO auth bypass, Zabbix 5.4.x; illustrative for default-creds + API abuse)
- CWE-1393: Use of Default Password

## Description
Zabbix ships with a default administrative account (`admin` / `zabbix`). Once
authenticated — trivially, given the default credentials — the Zabbix JSON-RPC
API (`/api_jsonrpc.php`) allows executing arbitrary scripts on any monitored
host via the `script.execute` API method.

The attack chain is:
1. Authenticate with default credentials `admin:zabbix` via the API.
2. Obtain an API auth token.
3. Call `script.execute` with a malicious command targeting any connected host.
4. Achieve RCE on monitored infrastructure.

CVE-2022-23131 additionally allows unauthenticated session hijacking via a
crafted SAML SSO cookie when SAML auth is enabled, further lowering the bar.

## Affected Service
- **Service:** Zabbix 5.0 frontend / JSON-RPC API
- **Port:** 80/TCP (default nginx/Apache frontend)
- **Vulnerable configuration:** default admin:zabbix password; unrestricted `/api_jsonrpc.php`

## Constraints
- The affected package must not be upgraded.
