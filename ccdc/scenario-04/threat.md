# Scenario 04: SSH X11 Forwarding Enabled + Excessive Authentication Attempts

## Vulnerability

Two SSH misconfigurations are present:

1. **X11 Forwarding Enabled**: The SSH daemon allows forwarding of X11
   graphical display connections. This exposes the server to X11 security
   vulnerabilities and can be used as an attack vector if the X11 client or
   server has vulnerabilities.

2. **Excessive Authentication Attempts**: The daemon allows a very large number
   of authentication attempts per connection, greatly facilitating brute-force
   password attacks.

## CWE Classification

### CWE-307: Improper Restriction of Excessive Authentication Attempts

The permissive attempt limit allows an attacker to make many password guesses
per SSH connection, significantly reducing the time needed for a brute-force
attack. Combined with the unnecessary X11 forwarding, this represents an
inadequately hardened SSH configuration.

## Affected Service

OpenSSH Server (sshd)

## Constraints

- Normal SSH access must remain functional.

## References

- UTSA script.sh
- CIS Benchmark for Ubuntu - 5.2.6
- CIS Benchmark for Ubuntu - 5.2.7
