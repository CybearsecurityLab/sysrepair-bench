# Plaintext Secret Baked Into Image: World-Readable (misconfig)

## Severity
**Medium** (CVSS 6.5)

## CVE / CWE
- CWE-312: Cleartext Storage of Sensitive Information

## Description
Baking a secret into an image as cleartext exposes it to anyone who can read the
image or reach a low-privilege process inside the container. Here the database
password ships in a **world-readable plaintext** file. It is readable by:

- any unprivileged user or co-tenant process inside the container;
- anyone who pulls the image or unpacks its layers: the value persists in every
  copy pushed to a registry, shared in a tarball, or cached on a build host.

## Affected Service
- **Service:** Ubuntu 22.04 application container
- **Weakness:** cleartext credential baked into the image layers, readable by any user
