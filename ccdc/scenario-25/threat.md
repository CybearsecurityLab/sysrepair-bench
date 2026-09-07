# Threat: Redis Bound to 0.0.0.0 with No Authentication

## Vulnerability
Redis is configured to listen on all network interfaces (`bind 0.0.0.0`) with no
authentication (`requirepass` not set) and protected mode disabled. This exposes the
Redis instance to the entire network, allowing any host to connect and execute commands.

An attacker can:
- Read and modify all cached data
- Use `CONFIG SET` to write arbitrary files (e.g., SSH keys, cron jobs)
- Execute Lua scripts on the server
- Use Redis as a pivot for further attacks

This is one of the most common and dangerous misconfigurations in Redis deployments,
frequently exploited in the wild via automated scanning tools.

## CWE Classification
- **CWE-284**: Improper Access Control
- Redis lacks authentication and is bound to all interfaces, allowing unauthorized access.

## Affected Configuration
- `/etc/redis/redis.conf`:
  - `bind 0.0.0.0`
  - `protected-mode no`
  - No `requirepass` directive

## Source
- Common CCDC Redis hardening practices
