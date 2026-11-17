# ManageEngine Desktop Central 9, FileUploadServlet Arbitrary File Upload (CVE-2015-8249)

## Severity
**Critical** (CVSS 9.8)

## CVE
- **CVE-2015-8249**, Pre-authentication arbitrary file upload in the `FileUploadServlet`
  endpoint of ManageEngine Desktop Central prior to build 91100, leading directly to
  RCE as the Desktop Central service account (`LocalSystem` by default).

## Description
Desktop Central's `FileUploadServlet` accepts unauthenticated uploads and concatenates
a caller-supplied parameter into a filesystem path without canonicalization. An attacker
supplies a value containing path-traversal segments and a `.jsp` body; the servlet writes
the request body to a directory served by the bundled Tomcat and the JSP is executed on
next request.

The installed build is in the affected range. The admin console is left on 8020/TCP
reachable from all interfaces.

## Affected Service
- **Product:** ManageEngine Desktop Central (bundled Tomcat + PostgreSQL)
- **Services:** `DesktopCentralServer`, `MEDCServerComponent-Apache`,
  `MEDC Server Component - Notification Server`; all three are ordinary Windows services,
  started by the container's CMD and left Running.
- **Ports:** 8020/TCP (admin UI, via the bundled Apache), 8027/TCP (notification
  server). The 8040/TCP agent channel is not bound in this build.

## Constraints
- This host has no outbound network access and no `.ppm` service pack is staged on it.
- `sshd` (22) and `WinRM` (5985) are the operator's access to this host and must still be Running when you are done.
- If Desktop Central is taken out of use, no listener may remain on 8020/TCP or on the 8040/TCP agent channel.
