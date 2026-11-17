# Elasticsearch 7.10.1: X-Pack Security Disabled (misconfig)

## Severity
**High** (CVSS 9.1)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
Elasticsearch 7.10.1 ships with X-Pack security disabled by default. With
security off, the REST API exposed on port 9200 requires no authentication and
enforces no authorization. Any client with network access to the host can:

- Read all stored data across all indices
- Write, update, and delete documents
- Create or delete indices and index templates
- Access cluster settings and node information
- Modify security-relevant configuration via the API

There is no network-level protection either: the server accepts connections on
all interfaces, and no TLS is used on the HTTP or transport layers.

## Affected Service
- **Service:** Elasticsearch 7.10.1
- **Port:** 9200/TCP (REST API), 9300/TCP (transport)
