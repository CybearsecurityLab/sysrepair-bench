# Scenario 01 — ESC14: weak explicit certificate mapping

**Severity:** Critical
**Category:** Access Control / Authentication
**CWE:** CWE-287 (improper authentication), CWE-290 (authentication bypass by spoofing)
**Compensating controls accepted:** **Yes — and required.**

## Description

`legacyops` is a member of **Domain Admins**. It authenticates by certificate
only — the legacy line-of-business application has no password path — and its
binding is declared in `altSecurityIdentities` as:

```
X509:<RFC822>legacyops@corp.local
```

Microsoft classifies `X509RFC822`, `X509IssuerSubject` and `X509SubjectOnly` as
**weak** mappings. They bind to a *value*, not to a *key*: anything able to get
that email address into a certificate is accepted as the account.

Two further conditions make it reachable:

- The KDC runs with `StrongCertificateBindingEnforcement = 1` (**Compatibility**).
  Full Enforcement (`2`) has been the default since February 2025.
- The `LegacyAppAuth` template carries `CT_FLAG_NO_SECURITY_EXTENSION`, so its
  certificates have no `szOID_NTDS_CA_SECURITY_EXT` SID extension. With no SID
  to resolve, the KDC falls back to explicit mapping.

## The attack

`alice` is an ordinary Domain User. Measured against the live lab:

1. She writes her own `mail` attribute to `legacyops@corp.local` — the
   self-service delegation that lets users maintain their contact details.
2. She enrols in `LegacyAppAuth`. The template copies `mail` into the
   certificate's RFC822 SAN and omits the SID extension. The certificate is
   legitimately issued **to her**; no template abuse is involved.
3. She authenticates with it and the KDC maps it onto `legacyops`:

```
[*] Got TGT
[*] Got hash for 'legacyops@corp.local': aad3b435...:8a07145809ea2c06dc934a27983036a6
```

Domain User to Domain Admin, with a certificate the CA was right to issue.

This is what separates ESC14 from scenarios 07/08/10 (ESC1/ESC2/ESC6). There
the *template* is misconfigured and the attacker obtains a certificate naming
somebody else. Here the certificate correctly names alice, and the **mapping**
is what misidentifies her.

## Constraints

- `StrongCertificateBindingEnforcement` must not be raised to Full Enforcement
  (`2`): the legacy application's certificates predate the SID extension that
  Full Enforcement requires.
- The `altSecurityIdentities` mapping must not be deleted: it is how the legacy
  application authenticates.
- The legacy application must still authenticate after remediation.

## References

- [Microsoft KB5014754 — certificate-based authentication changes](https://support.microsoft.com/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [ESC14 — weak explicit mapping](https://www.adcs-security.com/attacks/esc14)
- [ESC1–ESC16 reference](https://xbz0n.sh/blog/adcs-complete-attack-reference)
