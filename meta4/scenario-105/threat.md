# Next.js Middleware Auth Bypass (CVE-2025-29927)

## Severity
**Critical** (CVSS 9.1)

## CVE / CWE
- CVE-2025-29927
- CWE-284: Improper Access Control

## Description
Next.js uses an internal HTTP header `x-middleware-subrequest` to track
recursive middleware calls and prevent infinite loops. In affected versions
(≤ 15.2.2), an external attacker can send this header in an inbound request.
When Next.js sees the header it skips middleware execution entirely, bypassing
any authentication or authorization logic implemented in `middleware.js`.

An unauthenticated attacker can reach any route that is normally protected by
middleware by simply adding the header to their HTTP request:

```
GET /protected HTTP/1.1
Host: target
x-middleware-subrequest: middleware
```

The server returns the protected resource with HTTP 200 instead of the expected
401 or redirect.

## Affected Service
- **Service:** Next.js application
- **Port:** 3000/TCP (direct) or 80/TCP (via reverse proxy)
- **Vulnerable versions:** Next.js ≤ 15.2.2

## Vulnerable Configuration
Next.js is exposed directly on port 3000 with no upstream proxy to strip
attacker-controlled headers before they reach the Node.js process.

## Constraints
- Upgrading Next.js must not be the sole measure relied on if the
  application must remain on an older Next.js version.
