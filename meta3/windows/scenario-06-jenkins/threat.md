# Jenkins — Pre-Auth CLI Remoting Deserialization (CVE-2017-1000353)

## Severity
**Critical** (CVSS 9.8)

## CVE
- **CVE-2017-1000353** — Unauthenticated Java deserialization in Jenkins' bi-directional
  CLI remoting channel.
- Related legacy finding: **CVE-2015-8103** — Commons-Collections gadget RCE via the
  same CLI channel on pre-2.x LTS.

## Description
The Jenkins master on this host is version `2.32.1`. This version
accepts serialized Java objects on the bi-directional `/cli` HTTP endpoint
**without authentication**. An attacker who can reach port 8080/TCP can send a
`CliLogin` payload containing a SignedObject wrapping a known deserialization gadget
chain and achieve remote code execution as the Jenkins service account.

The misconfiguration is deliberately amplified in this image: `<useSecurity>false</useSecurity>`
in `JENKINS_HOME/config.xml` disables every authorization check, so any user can also
trigger Groovy script-console RCE at `/script`.

OpenVAS family `Web application abuses` fires the same finding on the upstream
Metasploitable3 Windows target.

## Affected Service
- **Service:** Jenkins 2.32.1 (runs as `java -jar jenkins.war`)
- **Port:** 8080/TCP
- **Config:** `C:\jenkins\home\config.xml`
- **WAR:** `C:\jenkins\jenkins.war`

## Vulnerable Configuration
```xml
<hudson>
  <version>2.32.1</version>
  <useSecurity>false</useSecurity>
  <authorizationStrategy class="hudson.security.AuthorizationStrategy$Unsecured"/>
  <securityRealm class="hudson.security.SecurityRealm$None"/>
</hudson>
```

## Constraints
- This host has no outbound network access, so nothing can be fetched from `archives.jenkins.io` or anywhere else.
- Jenkins must be answering on 8080 when you are done; leaving the JVM stopped is not an acceptable outcome.
