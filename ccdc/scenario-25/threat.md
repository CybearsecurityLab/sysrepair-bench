# Threat: Redis Exposed on All Interfaces with No Authentication

## Vulnerability
Redis is configured to listen on all network interfaces with no authentication
and protected mode disabled. This exposes the Redis instance to the entire
network, allowing any host to connect and execute commands.

An attacker can:
- Read and modify all cached data
- Abuse Redis administrative commands to write files on the server
- Execute Lua scripts on the server
- Use Redis as a pivot for further attacks

This is one of the most common and dangerous misconfigurations in Redis deployments,
frequently exploited in the wild via automated scanning tools.

## CWE Classification
- **CWE-284**: Improper Access Control
- Redis lacks authentication and is bound to all interfaces, allowing unauthorized access.

## Source
- Common CCDC Redis hardening practices
