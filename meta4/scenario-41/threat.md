# CouchDB 3.1: Admin Party (misconfig)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CWE-1188: Initialization with Insecure Default

## Description
CouchDB has a well-known "Admin Party" state: when no administrator accounts
are defined, CouchDB treats every incoming HTTP request as if it originates
from a server administrator. No username, no password, and no authentication
header are required.

Any unauthenticated client that can reach port 5984 can:

- List and read all databases
- Create or delete any database
- Read, write, and delete every document
- Create new admin accounts, locking out legitimate users
- Trigger replication to exfiltrate the entire data set

The attack surface is the entire HTTP API.

## Affected Service
- **Service:** Apache CouchDB 3.1
- **Port:** 5984/TCP
