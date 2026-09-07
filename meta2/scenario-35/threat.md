# TWiki / Tiki Wiki Legacy Admin Exposure

## Severity
**High** — multiple CVEs (TWikiDraw/MAKETEXT RCE CVE-2008-5304, Tiki Wiki <4.x auth bypass, etc.)

## Category
Compensating Controls (major-version wiki upgrade breaks site content and plugin surface)

## Description
Metasploitable 2 exposes TWiki 01.Feb.2003 and Tiki Wiki 1.9.5 on port 80. These codebases
have been abandoned in their 1.x form; the only upstream "fix" is a major-version upgrade
that rewrites URLs, breaks installed plugins, and forces data migration — unacceptable for
an archival wiki that must keep serving historical content.

## Affected Service / Port
- Apache serving legacy TWiki/Tiki binaries
- Port 80/TCP
- The administrative, editing and installer surface that hosts the RCE and
  auth-bypass findings — `/twiki/bin/configure`, the `*/bin/edit` endpoints,
  and `*/tiki-install.php` — answers any client that can reach port 80.

## Constraints
- Public read access to `/twiki/bin/view/*` must remain available.

## Out of Scope
- Upgrading TWiki/Tiki to a supported major version (breaks content/plugins).
- Removing the wiki entirely.
