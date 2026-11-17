# Apache Documentation Directory Browsable

## Severity
**Medium** | CVSS 5.0

## CVE
CVE-1999-0678

## Description
The Apache HTTP server is configured to publish the system's installed package documentation directory with directory indexing enabled. This exposes the full directory listing of installed package documentation to any remote user. This information disclosure vulnerability reveals the exact packages and versions installed on the system, which an attacker can use to identify known vulnerabilities in specific software versions. On Debian/Ubuntu systems, the package documentation directory often contains changelogs, README files, and sometimes example configuration files that may reveal sensitive information about the system's configuration.

## Affected Service
- **Service:** Apache HTTP Server 2.2
- **Port:** 80/tcp
- **Protocol:** HTTP
