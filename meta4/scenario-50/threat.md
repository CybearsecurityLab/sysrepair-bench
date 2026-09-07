# Kafka — No SASL Authentication on the client listener (misconfig)

## Severity
**High** (CVSS 8.6)

## CVE / CWE
- CWE-284: Improper Access Control

## NOTE — version reality
The image is `apache/kafka` (pinned by digest; Kafka 4.3.1 as built). The "3.5"
in the original title is historical: the official `apache/kafka` image only
exists from 3.7.0 onward, so a 3.5 image was never available. In Kafka 4.x the
KRaft broker also does not support the legacy ZooKeeper class
`kafka.security.authorizer.AclAuthorizer` (replaced by
`org.apache.kafka.metadata.authorizer.StandardAuthorizer`).

## Description
Apache Kafka 3.5 ships with a `PLAINTEXT` listener and no authentication or
authorization configured by default. Any client with network access to port 9092
can produce messages to any topic, consume from any topic (including internal
topics such as `__consumer_offsets`), create and delete topics, and alter
partition assignments — all without supplying any credentials.

Combined with no ACL authorizer, there is no mechanism to distinguish legitimate
producers/consumers from malicious ones. An attacker can:
- Exfiltrate all messages by subscribing to every topic
- Inject malicious messages into any queue
- Disrupt processing by deleting or compacting topics
- Read `__consumer_offsets` to track consumer group progress and tamper with offsets

The attack requires only a standard Kafka client library:
```
kafka-console-consumer.sh --bootstrap-server <host>:9092 --topic <any-topic> --from-beginning
```

## Affected Service
- **Service:** Apache Kafka 3.5
- **Port:** 9092/TCP
- **Vulnerable configuration:** `PLAINTEXT` listener, no `sasl.enabled.mechanisms`, no `authorizer.class.name`

## Vulnerable Configuration
- `listeners=PLAINTEXT://:9092` — no SASL protocol
- `sasl.enabled.mechanisms` not set
- `authorizer.class.name` not set — all clients have full access
- `allow.everyone.if.no.acl.found=true` (effective default)
