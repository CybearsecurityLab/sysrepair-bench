# Scenario 32: AppArmor Not Enforcing

## Vulnerability
AppArmor is installed but not actively enforcing any profiles. All profiles are set to complain mode or disabled entirely. Without enforced Mandatory Access Control (MAC) profiles, applications run without confinement, allowing potential exploits to access any resource the process user can access. AppArmor enforcement is a critical defense-in-depth layer that limits the damage from compromised applications.

## CWE Classification
- **CWE-693**: Protection Mechanism Failure
- The MAC protection mechanism is present but not operational, rendering it ineffective.

## Affected Components
- `/etc/apparmor.d/` - AppArmor profile definitions (set to complain mode)
- `apparmor` service - AppArmor framework (not enforcing)
- `aa-status` - Shows no enforced profiles

## References
- CIS Ubuntu Linux Benchmark - Section 1.6 (Mandatory Access Control)
- NIST SP 800-53 - AC-3 (Access Enforcement)
- TAMU cfg_apparmor.sh
