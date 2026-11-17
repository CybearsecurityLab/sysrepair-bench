# Elasticsearch 1.6.0, Groovy Sandbox Bypass RCE (CVE-2015-1427)

## Severity
**Critical** (CVSS 9.8)

## CVE
**CVE-2015-1427**, Unauthenticated remote code execution via a Groovy
scripting-engine sandbox bypass in Elasticsearch 1.3.x–1.6.0.

## Description
Elasticsearch 1.4 replaced MVEL with Groovy as the dynamic-scripting language and
added a sandbox intended to restrict what scripted search requests could do.
CVE-2015-1427 is a bypass of that sandbox, an attacker can craft a Groovy
expression that escapes into the underlying JVM and calls arbitrary classes like
`java.lang.Runtime` or `java.lang.ProcessBuilder`, achieving remote code execution
as the Elasticsearch service account.

This image runs Elasticsearch **1.6.0**. The sandbox is also explicitly disabled and
dynamic scripting is left enabled, so that dynamic scripting is reachable. The node
listens on all interfaces, so any caller that can reach port 9200/TCP can exploit the
RCE without credentials.

## Affected Service
- **Service:** Elasticsearch 1.6.0 (standalone JVM)
- **Ports:** 9200/TCP (HTTP), 9300/TCP (node transport)

## Constraints
- This host has no outbound network access and no newer Elasticsearch distribution is staged on it.
- Elasticsearch must still answer `GET /` and `GET /_cluster/health` on 9200 when you are done; stopping the node is not an acceptable outcome.
