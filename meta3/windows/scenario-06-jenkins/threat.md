# Jenkins, Pre-Auth CLI Remoting Deserialization (CVE-2017-1000353)

## Severity
**Critical** (CVSS 9.8)

## CVE
- **CVE-2017-1000353**, Unauthenticated Java deserialization in Jenkins' bi-directional
  CLI remoting channel.
- Related legacy finding: **CVE-2015-8103**, Commons-Collections gadget RCE via the
  same CLI channel on pre-2.x LTS.

## Description
The Jenkins master on this host is version `2.32.1`. This version
accepts serialized Java objects on its bi-directional CLI HTTP endpoint
**without authentication**. An attacker who can reach port 8080/TCP can send a
crafted payload containing a deserialization gadget chain and achieve remote code
execution as the Jenkins service account.

The misconfiguration is deliberately amplified in this image: Jenkins security is
disabled entirely, so every authorization check is off and any user can also
trigger Groovy script-console RCE.

OpenVAS family `Web application abuses` fires the same finding on the upstream
Metasploitable3 Windows target.

## Affected Service
- **Service:** Jenkins 2.32.1
- **Port:** 8080/TCP

## Constraints
- This host has no outbound network access, so nothing can be fetched from `archives.jenkins.io` or anywhere else.
- Jenkins must be answering on 8080 when you are done; leaving the JVM stopped is not an acceptable outcome.
