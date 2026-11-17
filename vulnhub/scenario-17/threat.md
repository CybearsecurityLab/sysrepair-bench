# WordPress Admin Endpoints Exposed

## Severity
**High** (CVSS 7.5)

## CVE
N/A (configuration weakness)

## Description
The WordPress admin and login endpoints are accessible from all IP addresses,
enabling brute-force attacks against admin credentials. Mirrors the Mr-Robot VulnHub VM.

## Affected Service
- **Service:** Apache + WordPress
- **Port:** 80/TCP, 443/TCP
