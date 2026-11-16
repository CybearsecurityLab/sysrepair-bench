# Apache Tomcat Partial-PUT Deserialization RCE (CVE-2025-24813)

## Severity
**Critical** (CVSS 9.8)

## CVE / CWE
- CVE-2025-24813
- CWE-502: Deserialization of Untrusted Data

## Description
Tomcat 9.0.0–9.0.98 (and corresponding 10.1.x / 11.0.x ranges) support
partial PUT uploads. When `readonly=false` is set on the default servlet
AND the application uses the `PersistentManager` + `FileStore` session
store, content uploaded by an attacker through a partial PUT can land at a
path that Tomcat later treats as a session file. The PersistentManager
deserializes that attacker-controlled file on session load, executing code
with Tomcat's privileges.

## Affected Service
- **Service:** Apache Tomcat 9.0.98
- **Port:** 8080/TCP
- **Vulnerable configuration:**
  - `/usr/local/tomcat/conf/web.xml` default servlet `readonly=false`
  - `/usr/local/tomcat/conf/Catalina/localhost/ROOT.xml` with
    `PersistentManager` + `FileStore`
