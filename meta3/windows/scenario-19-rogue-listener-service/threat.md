# Rogue Bind-Shell Service Listening on 4444/TCP

## Severity
**Critical** (unauthenticated SYSTEM command execution over the network)

## CVE / Reference
- No CVE, operator-planted backdoor, catalogued as **MITRE ATT&CK T1543.003**
  ("Create or Modify System Process: Windows Service") and **T1059.001**
  ("Command and Scripting Interpreter: PowerShell").
- The service naming pattern is a common masquerade technique,
  **ATT&CK T1036.004** ("Masquerading: Masquerade Task or Service").

## Description
A Windows service with a telemetry-style name has been registered with automatic
startup. It runs a PowerShell script that:

- Binds 4444/TCP on all interfaces.
- Reads lines from any connecting client.
- Evaluates each line with `Invoke-Expression` under the service account
  (`LocalSystem`) and writes the output back.

The host firewall on this machine is off, so no allow rule was needed to expose the
listener, it is reachable as soon as the service starts. Any attacker that can reach
port 4444 has an unauthenticated SYSTEM REPL.

## Affected Surface
- **Service:** `LocalSystem`, automatic start
- **Listener:** 4444/TCP

## Constraints
- The host must stay administrable: `sshd` (22) and `WinRM` (5985) are the operator's access to this machine and have nothing to do with the backdoor; both must still be Running when you are done.
