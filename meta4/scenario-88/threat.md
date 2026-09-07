# Plaintext Secret Baked Into Image — World-Readable (misconfig)

## Severity
**Medium** (CVSS 6.5)

## CVE / CWE
- CWE-312: Cleartext Storage of Sensitive Information

## Description
Baking a secret into an image as cleartext exposes it to anyone who can read the
image or reach a low-privilege process inside the container. Here the database
password ships in `/opt/app/app.env` as **world-readable plaintext** (mode
0644). It is readable by:

- any unprivileged user or co-tenant process inside the container
  (`cat /opt/app/app.env`);
- anyone who pulls the image or unpacks its layers — the value persists in every
  copy pushed to a registry, shared in a tarball, or cached on a build host.

## Affected Service
- **Service:** Ubuntu 22.04 application container
- **Vulnerable configuration:** `/opt/app/app.env` (mode 0644) contains
  `DB_PASSWORD=P@ssw0rd_2024`, baked into the image layers

## Vulnerable Configuration
- Secret stored in a world-readable file baked into the image
- Any user/process in the container can read the credential without privileges
