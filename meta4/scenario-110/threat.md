# ImageMagick — Permissive policy.xml (CVE-2023-34152)

## Severity
**High** (CVSS 8.8)

## CVE / CWE
- CVE-2023-34152
- CWE-94: Improper Control of Generation of Code

## Description
ImageMagick uses a `policy.xml` file to restrict which image coders and
resources are available. When the policy is absent or overly permissive,
dangerous coders such as **MVG** (Magick Vector Graphics), **MSL**
(Magick Scripting Language), and **URL** (remote resource fetch) remain
enabled. An attacker who can supply a crafted image path or filename to any
ImageMagick invocation can exploit these coders to achieve arbitrary code
execution on the host.

CVE-2023-34152 specifically covers the `url` coder allowing server-side
request forgery (SSRF) and arbitrary command injection through shell
metacharacters in filenames handed to `convert` or `identify`. Combined with
the `mvg:` and `msl:` coders, an attacker can embed payloads such as:

```
convert 'msl:/tmp/evil.msl' output.png
convert 'mvg:evil.mvg' output.png
```

Both succeed silently when no coder restriction is in place, executing
attacker-controlled commands with the privileges of the ImageMagick process.

## Affected Service
- **Service:** ImageMagick (libMagickCore 6.x / 7.x)
- **Trigger:** Any call to `convert`, `identify`, `montage`, or `mogrify`
  with attacker-controlled input
- **Vulnerable configuration:** `/etc/ImageMagick-6/policy.xml` absent or
  containing no `rights="none"` entries for MVG, MSL, URL coders
