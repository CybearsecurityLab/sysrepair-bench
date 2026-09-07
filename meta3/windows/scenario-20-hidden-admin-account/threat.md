# Hidden Local Administrator — `support$` Account with RID-Hiding Suffix

## Severity
**Critical** (persistent unauthorized administrative access)

## CVE / Reference
- No CVE — operator-planted persistence, catalogued as **MITRE ATT&CK T1136.001**
  ("Create Account: Local Account") combined with **T1078.003**
  ("Valid Accounts: Local Accounts").
- The `$`-suffix naming trick is documented in DFIR literature as a visibility
  evasion technique: `net user` enumerates SAM accounts but certain legacy tools
  and admin GUIs filter out names ending in `$` under the assumption that they are
  machine accounts.

## Description
A local account named **`support$`** has been created with the following properties:

- Member of `BUILTIN\Administrators` (full local admin).
- Password `P@ssw0rd!` set to never expire and not user-changeable.
- Description masquerades as a legitimate "break-glass support account."
- The `$` suffix makes the account easy to miss in older admin tools that filter
  out machine-account naming patterns.

Any attacker with the password has interactive and network logon rights as a local
administrator (RDP on 3389, WinRM on 5985, SMB/PsExec on 445). Because the account
is local, it does not appear in domain-controller audit logs — only on this host —
so the blast radius is exactly one machine, but detection is entirely dependent on
host-level SAM auditing.

## Affected Surface
- **Account:** `support$` in the local SAM
- **Group membership:** `BUILTIN\Administrators`
- **Logon rights:** console, RDP, WinRM, SMB
