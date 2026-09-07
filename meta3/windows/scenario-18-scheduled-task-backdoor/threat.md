# Scheduled Task Backdoor — Hidden SYSTEM Task Launching Payload from `C:\Users\Public`

## Severity
**High** (persistent SYSTEM-level code execution)

## CVE / Reference
- No CVE — operator-planted persistence, catalogued as **MITRE ATT&CK T1053.005**
  ("Scheduled Task/Job: Scheduled Task").
- Payload staging directory corresponds to **T1074** ("Data Staged: Local Data
  Staging").

## Description
A scheduled task named `Windows Update Assistant` has been registered under
`\Microsoft\Windows\UpdateOrchestrator\` — a path that blends in with real Microsoft
tasks — with the following properties:

- Runs as `NT AUTHORITY\SYSTEM` at highest integrity.
- Triggers at every user logon **and** every hour, indefinitely.
- Marked `Hidden`, so `schtasks /query` without `/v` omits it in some views.
- Executes a PowerShell script at `C:\Users\Public\Updater\updater.ps1` — a
  world-writable staging directory (BUILTIN\Users have Modify).

The immediate payload only writes a heartbeat log, but the combination of a
SYSTEM-level execution primitive plus a user-writable payload file means any local
user can overwrite `updater.ps1` with arbitrary code and wait for the next hourly
trigger to escalate to SYSTEM.

## Affected Surface
- **Task:** `\Microsoft\Windows\UpdateOrchestrator\Windows Update Assistant`
- **Payload file:** `C:\Users\Public\Updater\updater.ps1`
- **Payload directory ACL:** `C:\Users\Public\Updater` grants `BUILTIN\Users:(OI)(CI)M`
