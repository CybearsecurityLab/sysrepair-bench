# Cassandra 3.11: Unauthenticated Access and UDF RCE (CVE-2021-44521)

## Severity
**Critical** (CVSS 9.1)

## CVE / CWE
- CVE-2021-44521
- CWE-1188: Initialization with Insecure Default

## Description
Apache Cassandra 3.11 ships with authentication and authorization providers
that allow everyone by default, meaning any client that reaches port 9042 can
connect without supplying credentials and is granted full privileges over the
cluster.

CVE-2021-44521 compounds this misconfiguration: when user-defined functions
are enabled, a connected client can define a User-Defined Function (UDF)
written in Java and have the Cassandra node execute it inside its JVM.
Because the UDF sandbox is bypassable, an attacker can escape the sandbox and
run arbitrary OS commands as the Cassandra process user.

Combined, the two weaknesses allow an unauthenticated attacker to achieve
remote code execution without any credentials.

## Affected Service
- **Service:** Apache Cassandra 3.11
- **Port:** 9042/TCP (CQL native transport)
