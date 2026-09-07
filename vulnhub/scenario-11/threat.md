# Nginx Serves Hidden Dotfiles

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness)

## Description
Nginx serves hidden dotfiles from the web root, so secrets committed alongside the
application are downloadable over HTTP — e.g. `/.env` (application/DB credentials) and
`/.git/config` (repository metadata and remotes). There is no `location` rule denying
access to dot-prefixed paths.

> Note: nginx normalizes `../` in request paths, so classic directory traversal outside the
> web root is not exploitable against a default nginx — the real, exploitable exposure here
> is the served dotfiles.

Mirrors the DC-5 VulnHub VM class of Nginx information-disclosure misconfigurations.

## Affected Service
- **Service:** Nginx + PHP-FPM
- **Port:** 80/TCP
- **Configuration:** /etc/nginx/sites-available/default
