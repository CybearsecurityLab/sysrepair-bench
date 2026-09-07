# scenario-13-ad-dc-win2019 — divergent invocation

Unlike the Docker-native scenarios, this one is a **Hyper-V VM** built with
AutomatedLab: Active Directory Domain Services cannot be hosted inside a
Windows Server-Core container (no `ADDSDeployment` module support, no reboot
semantics). The former Vagrant/VirtualBox path has been retired — see
`lab/Hs13Lab.ps1`.

## Prereqs

- Windows host with Hyper-V enabled; **elevated** PowerShell
- The AutomatedLab module (and its LabSources folder + a Windows Server 2019
  evaluation ISO — same prerequisites as `meta4/ad-vm/`, see
  `meta4/ad-vm/lab/RUNBOOK.md`)

## Build flow

```powershell
# 1. Generate roles.json + render task.md (same as Docker scenarios)
bash hivestorm/prepare.sh 13     # or: pwsh hivestorm/prepare.ps1 13

# 2. Build the DC (one-time): AutomatedLab creates the forest
cd hivestorm\scenario-13-ad-dc-win2019
powershell -ExecutionPolicy Bypass -File .\lab\Hs13Lab.ps1

# 3. Capture the clean (pre-seed) baseline checkpoint, then seed
. .\lab\Hs13Ops.ps1
Save-Hs13Baseline
Invoke-Hs13Seed -RolesPath .\build\roles.json
```

At eval time `task.py` reads `lab/automatedlab.json` and calls
`Restore-Hs13Baseline`, `Install-Hs13SshAccess`, and `Set-Hs13PortProxy`
itself; the agent runs in a Linux bridge container and SSHes to the DC on
`host.docker.internal:2223`. Note the restore returns the DC to the
**pre-seed** baseline, so re-run `Invoke-Hs13Seed` for the session's
`build/roles.json`.

## Running the verifier

The Inspect-AI harness uploads and runs `verify.ps1` on the DC (inlining
`lib/verifylib.ps1`). For manual runs, from an elevated PowerShell:

```powershell
. .\lab\Hs13Ops.ps1
Invoke-Hs13Verify
```

JSONL output is captured and scored by `hivestorm_weighted_scorer`.

## Scope caveats

- **Single-DC / single-domain only.** Cross-forest trusts, child domains,
  and RODCs are out of scope for sysrepair-bench and deferred to a future
  `hivestorm-ad/` suite.
- **Krbtgt dual rotation** is documented in the scoring rubric but only a
  single rotation is checked — full dual-rotation testing requires replay
  of Kerberos tickets, which the harness does not orchestrate.
- **LAPS** is represented as "not deployed" rather than "deployed but
  misconfigured" — the agent is credited for either installing LAPS or
  documenting via a decoy registry marker that a manual workflow exists.
