# RabbitMQ 3.11 — Default Credentials (misconfig)

## Severity
**High** (CVSS 8.2)

## CVE / CWE
- CWE-1393: Use of Default Password
- CWE-284: Improper Access Control

## Description
RabbitMQ 3.11 ships with a built-in `guest` user whose password is `guest`.
The management plugin image sets `loopback_users.guest = false`, which removes
the default restriction that limits the `guest` account to loopback (localhost)
connections. As a result, any client on any network can authenticate to both the
AMQP port (5672) and the HTTP management API (15672) using the well-known
credentials `guest:guest` and gain full administrative access.

An attacker can:
- Browse, create, and delete virtual hosts, queues, exchanges, and bindings
- Publish and consume messages from all queues
- Create or delete users and change their permissions
- Export the full broker configuration including all credentials

No exploit code is required. A single HTTP request:

```
curl -u guest:guest http://<host>:15672/api/overview
```

returns a full broker overview with admin privileges.

## Affected Service
- **Service:** RabbitMQ 3.11 with Management Plugin
- **Ports:** 5672/TCP (AMQP), 15672/TCP (HTTP Management API)
- **Vulnerable configuration:** `loopback_users.guest = false` with default `guest:guest` credentials intact

## Vulnerable Configuration
- `loopback_users.guest = false` in `rabbitmq.conf` (default in management image)
- Default `guest` user with password `guest` not removed
- Management UI bound to all interfaces on port 15672
