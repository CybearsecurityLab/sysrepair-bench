# ManageEngine Desktop Central 9 — FileUploadServlet Arbitrary File Upload (CVE-2015-8249)

## Severity
**Critical** (CVSS 9.8)

## CVE
- **CVE-2015-8249** — Pre-authentication arbitrary file upload in the `FileUploadServlet`
  endpoint of ManageEngine Desktop Central prior to build 91100, leading directly to
  RCE as the Desktop Central service account (`LocalSystem` by default).

## Description
Desktop Central's `FileUploadServlet` accepts unauthenticated uploads and concatenates
the caller-supplied `connectionId` parameter into a filesystem path without
canonicalization. An attacker supplies a `connectionId` containing path-traversal
segments and a `.jsp` body; the servlet writes the request body to a directory served
by the bundled Tomcat and the JSP is executed on next request.

The Rapid7 mirror this image installs from serves a version-less object; what it
actually lays down reports `buildnumber=91084` in `conf\product.conf`, which is in the
affected range. The admin console is left on 8020/TCP bound to `0.0.0.0`.

## Affected Service
- **Install root:** `C:\ManageEngine\DesktopCentral_Server` (bundled Tomcat + PostgreSQL)
- **Services:** `DesktopCentralServer`, `MEDCServerComponent-Apache`,
  `MEDC Server Component - Notification Server`
- **How it is actually running here:** all three services are ordinary Windows services,
  started by the container's CMD and left Running. `DesktopCentralServer` is the Tanuki
  wrapper plus the product JVM; `MEDCServerComponent-Apache` is the front-end httpd that
  owns **8020** and reverse-proxies to the JVM.
- **Ports:** 8020/TCP (admin UI, via the bundled Apache), 8027/TCP (notification
  server). The 8040/TCP agent channel is not bound in this build.
- **Vulnerable endpoint:** `POST /fileupload?connectionId=...` — this is the real
  mapping. `webapps\DesktopCentral\WEB-INF\web.xml` binds `<url-pattern>/fileupload`
  to `com.adventnet.sym.webclient.common.FileUploadServlet`; the
  `/agent/connection/download/FileUploadServlet` path quoted by some CVE write-ups is
  **404 here**.

## Constraints
- This host has no outbound network access and no `.ppm` service pack is staged on it.
- `sshd` (22) and `WinRM` (5985) are the operator's access to this host and must still be Running when you are done.
- If Desktop Central is taken out of use, no listener may remain on 8020/TCP or on the 8040/TCP agent channel.
