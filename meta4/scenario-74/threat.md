# Plaintext Secret Shipped In A World-Readable File — CWE-312

## Severity
**High** (CVSS 8.8)

## CVE / CWE
- CWE-312: Cleartext Storage of Sensitive Information

## Description
Baking a secret into an image as cleartext exposes it to anyone who can read the
image or reach a low-privilege process inside the container. Here a database
password and API key ship in `/etc/appsecrets/db.conf` as **world-readable
plaintext** (mode 0644). They are readable by:

- any unprivileged user or co-tenant process inside the container
  (`cat /etc/appsecrets/db.conf`);
- anyone who pulls the image or unpacks its layers — the value persists in every
  copy pushed to a registry, shared in a tarball, or cached on a build host.

## Affected Service
- **Service:** Ubuntu 22.04 application container (`/usr/local/bin/appd.sh`)
- **Vulnerable configuration:** `/etc/appsecrets/db.conf` (mode 0644) contains
  `DB_PASSWORD=SuperSecret123` and `API_KEY=sk-live-abc123`, baked into the image
  layers.

## Vulnerable Configuration
- Secret stored in a world-readable file baked into the image
- Any user/process in the container can read the credential without privileges

> Design note: an earlier version of this scenario baked the secrets into image
> `ENV` instructions (`ENV DB_PASSWORD=...`). A baked image `ENV` is injected by
> Docker into every process environment and `/proc/1/environ` and **cannot be
> removed by any in-container remediation** — only an image rebuild removes it —
> which made the scenario unsolvable inside the running container. The
> world-readable secret file models the same cleartext-storage weakness
> (CWE-312) while being remediable at runtime (the same reframe applied to
> meta4/scenario-88, with a distinct secret and path so the two scenarios remain
> independent).
