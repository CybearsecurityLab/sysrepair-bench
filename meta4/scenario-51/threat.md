# Mosquitto 2.0: Anonymous Pub/Sub (misconfig)

## Severity
**High** (CVSS 8.2)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
Eclipse Mosquitto 2.0 permits anonymous clients, so any MQTT client can
connect to the broker on port 1883 without supplying a username or password.
With no access control list in place, every anonymous client has full publish
and subscribe rights over every topic, including wildcard subscriptions.

This misconfiguration allows an attacker with network access to:
- Subscribe to all topics and eavesdrop on all MQTT messages, potentially
  harvesting sensor data, telemetry, or application state
- Publish arbitrary messages to any topic, injecting false data into IoT
  pipelines, triggering actuators, or corrupting application queues
- Enumerate topic structure by watching retained messages

No TLS is used, so traffic is transmitted in plaintext and trivially
intercepted on any shared network segment.

## Affected Service
- **Service:** Eclipse Mosquitto 2.0
- **Port:** 1883/TCP (MQTT plaintext)
