# Docker ARG Secret in Layers (misconfig)

## Severity
**Medium** (CVSS 6.5)

## CVE / CWE
- CWE-312: Cleartext Storage of Sensitive Information

## Description
Docker `ARG` instructions pass build-time variables into `RUN` commands. Unlike
`ENV`, the value does not appear in the final image's environment, but it is
permanently embedded in the image layer created by the `RUN` instruction that
consumed it. Anyone with access to the image can recover the secret from the
image history.

The layer diff shows the full shell command including the argument value.
Even if a subsequent `RUN` step overwrites or deletes the file, the original
layer (and thus the secret) remains in the image and is recoverable by
exporting the image tarball and inspecting individual layer tarballs.

## Affected Service
- **Service:** Ubuntu 22.04 application container
- **Weakness:** a build-time secret argument embedded in an image layer
