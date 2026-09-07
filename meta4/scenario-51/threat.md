# Mosquitto 2.0 — Anonymous Pub/Sub (misconfig)

## Severity
**High** (CVSS 8.2)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
Eclipse Mosquitto 2.0 is configured with `allow_anonymous true`, permitting any
MQTT client to connect to the broker on port 1883 without supplying a username
or password. Combined with the absence of an ACL file, every anonymous client
has full publish and subscribe rights over every topic, including wildcard
subscriptions (`#`).

This misconfiguration allows an attacker with network access to:
- Subscribe to `#` and eavesdrop on all MQTT messages across all topics,
  potentially harvesting sensor data, telemetry, or application state
- Publish arbitrary messages to any topic, injecting false data into IoT
  pipelines, triggering actuators, or corrupting application queues
- Enumerate topic structure by watching retained messages

There is no exploit to craft — a standard MQTT client suffices:
```
mosquitto_sub -h <host> -t '#' -v
mosquitto_pub -h <host> -t any/topic -m "injected"
```

No TLS is configured, so traffic is transmitted in plaintext and trivially
intercepted on any shared network segment.

## Affected Service
- **Service:** Eclipse Mosquitto 2.0
- **Port:** 1883/TCP (MQTT plaintext)
- **Vulnerable configuration:** `allow_anonymous true`, no password file, no ACL file

## Vulnerable Configuration
- `allow_anonymous true` in `mosquitto.conf`
- No `password_file` directive
- No `acl_file` directive
- Listener bound to all interfaces on port 1883
