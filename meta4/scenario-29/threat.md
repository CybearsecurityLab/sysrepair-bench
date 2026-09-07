# DVGA — GraphQL Introspection & Unbounded Query (OWASP GraphQL top issues)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-200: Exposure of Sensitive Information (introspection)
- CWE-400: Uncontrolled Resource Consumption (unbounded queries)

## Description
DVGA ships with the default-insecure GraphQL posture that the OWASP
GraphQL cheat sheet warns against:

1. **Introspection** is enabled — any unauthenticated client can query
   `{ __schema { types { name } } }` to enumerate every type, field,
   and argument of the API, easing follow-up attacks.
2. **Unbounded queries**: no depth or complexity limit, so a client can
   send a deeply nested / heavily aliased query that pins a CPU core
   and slows all other requests.

## Affected Service
- **Port:** 5013/TCP
- **Endpoint:** `/graphql`
