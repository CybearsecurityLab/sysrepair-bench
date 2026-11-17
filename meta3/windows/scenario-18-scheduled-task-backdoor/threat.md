# Scheduled Task Backdoor, Hidden SYSTEM Task Launching a User-Writable Payload

## Severity
**High** (persistent SYSTEM-level code execution)

## CVE / Reference
- No CVE, operator-planted persistence, catalogued as **MITRE ATT&CK T1053.005**
  ("Scheduled Task/Job: Scheduled Task").
- Payload staging directory corresponds to **T1074** ("Data Staged: Local Data
  Staging").

## Description
A scheduled task has been registered under a name and folder that blend in with real
Microsoft tasks, with the following properties:

- Runs as `NT AUTHORITY\SYSTEM` at highest integrity.
- Triggers at every user logon **and** every hour, indefinitely.
- Marked `Hidden`, so `schtasks /query` without `/v` omits it in some views.
- Executes a PowerShell script from a world-writable staging directory, where ordinary
  users have Modify rights.

The immediate payload only writes a heartbeat log, but the combination of a
SYSTEM-level execution primitive plus a user-writable payload file means any local
user can overwrite the script with arbitrary code and wait for the next hourly
trigger to escalate to SYSTEM.
