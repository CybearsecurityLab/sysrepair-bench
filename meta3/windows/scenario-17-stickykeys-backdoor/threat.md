# Sticky Keys Backdoor, Accessibility Binary Hijack Giving a Pre-Auth SYSTEM Shell

## Severity
**Critical** (pre-auth SYSTEM shell at the logon screen)

## CVE / Reference
- No CVE, this is a classic post-exploitation persistence technique catalogued as
  **MITRE ATT&CK T1546.008** ("Event Triggered Execution: Accessibility Features").
- Routinely used alongside other accessibility tools (on-screen keyboard, narrator,
  magnifier, utility manager), any of the accessibility binaries that winlogon will
  launch from a locked desktop.

## Description
Pressing Shift five times at the logon screen triggers the Sticky Keys handler under the
**winlogon** session, which runs as `NT AUTHORITY\SYSTEM`. If that launch can be
redirected to a shell, an attacker who can reach the console or an RDP pre-auth banner
gets an interactive SYSTEM shell without supplying a single credential.

The technique has two variants. The classic one overwrites the accessibility binary
itself with a copy of the command shell. The variant deployed on **this** host is the
registry form: a debugger redirection has been planted for more than one accessibility
executable. That is a supported mechanism for attaching a debugger to a named image;
pointing it at a shell produces the same pre-auth SYSTEM shell with the on-disk binaries
left byte-for-byte genuine, so file hashing and `sfc` will report nothing wrong.

This is Server Core, which ships no accessibility executables at all, so there is
nothing on disk to inspect. The hijack lives entirely in the registry and would fire
the moment this configuration reached a Desktop Experience or RDP-enabled host.

On hosts where the binaries do exist, the file-swap variant instead replaces the
accessibility binary with a copy of the command shell.

## Affected Surface
- **Trigger:** Shift × 5 (or the Ease-of-Access button) at logon / lock screen, local
  console or RDP banner.
- **Runs as:** `NT AUTHORITY\SYSTEM`.

## Constraints
- The `Image File Execution Options` key itself must not be deleted: that hive is the supported mechanism for attaching a debugger and for per-image AppCompat settings.
