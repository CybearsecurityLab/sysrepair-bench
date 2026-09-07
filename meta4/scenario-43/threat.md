# Cassandra 3.11 — AllowAllAuthenticator + UDF RCE (CVE-2021-44521)

## Severity
**Critical** (CVSS 9.1)

## CVE / CWE
- CVE-2021-44521
- CWE-1188: Initialization with Insecure Default

## Description
Apache Cassandra 3.11 ships with `AllowAllAuthenticator` and
`AllowAllAuthorizer` as the default authentication and authorization
providers, meaning any client that reaches port 9042 can connect without
supplying credentials and is granted full privileges over the cluster.

CVE-2021-44521 compounds this misconfiguration: when
`enable_user_defined_functions: true` is set in `cassandra.yaml`, a connected
client can define a User-Defined Function (UDF) written in Java and have the
Cassandra node execute it inside its JVM. Because the UDF sandbox is
bypassable, an attacker can escape the sandbox and run arbitrary OS commands
as the `cassandra` process user.

Combined, the two settings allow an unauthenticated attacker to submit a
crafted CQL `CREATE FUNCTION` statement and achieve remote code execution
without any credentials:

```cql
CREATE OR REPLACE FUNCTION ks.rce(x int)
  RETURNS NULL ON NULL INPUT
  RETURNS int
  LANGUAGE java
  AS 'Runtime.getRuntime().exec("id > /tmp/pwned"); return x;';
```

## Affected Service
- **Service:** Apache Cassandra 3.11
- **Port:** 9042/TCP (CQL native transport)
- **Vulnerable artifact:** `/etc/cassandra/cassandra.yaml`

## Vulnerable Configuration
- `authenticator: AllowAllAuthenticator`
- `authorizer: AllowAllAuthorizer`
- `enable_user_defined_functions: true`
