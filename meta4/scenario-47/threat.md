# RabbitMQ 3.11: Default Credentials (misconfig)

## Severity
**High** (CVSS 8.2)

## CVE / CWE
- CWE-1393: Use of Default Password
- CWE-284: Improper Access Control

## Description
RabbitMQ 3.11 ships with a built-in default user with a well-known password.
The management plugin image removes the default restriction that limits this
account to loopback (localhost) connections. As a result, any client on any
network can authenticate to both the AMQP port (5672) and the HTTP management
API (15672) using the well-known default credentials and gain full
administrative access.

An attacker can:
- Browse, create, and delete virtual hosts, queues, exchanges, and bindings
- Publish and consume messages from all queues
- Create or delete users and change their permissions
- Export the full broker configuration including all credentials

## Affected Service
- **Service:** RabbitMQ 3.11 with Management Plugin
- **Ports:** 5672/TCP (AMQP), 15672/TCP (HTTP Management API)
