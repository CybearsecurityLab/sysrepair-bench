# Threat: Kernel ASLR Disabled

## Vulnerability
Address Space Layout Randomization (ASLR) has been disabled by setting
`kernel.randomize_va_space = 0` in sysctl.conf. ASLR is a critical security mechanism
that randomizes the memory addresses used by processes, making it significantly harder
for attackers to exploit memory corruption vulnerabilities (buffer overflows, use-after-free,
etc.). With ASLR disabled, memory layouts are predictable, allowing attackers to reliably
craft exploits targeting specific memory addresses.

## CWE Classification
- **CWE-330**: Use of Insufficiently Random Values
- Disabling ASLR removes randomness from the virtual memory layout of processes.

## Affected Configuration
- `/etc/sysctl.conf` contains:
  - `kernel.randomize_va_space = 0`
  - Value `0` = no randomization

## Source
- TAMU sysctl.sh
- UTSA script.sh
