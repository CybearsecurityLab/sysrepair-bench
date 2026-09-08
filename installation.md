# SysRepair-Bench — Installation Guide

This guide walks through everything you need to install, and **which host runs
which suite**. It complements the high-level "Set-up" section in
[README.md](README.md) with concrete, copy-pastable commands.

## What you need depends on what you are doing

| Task | Needs |
|---|---|
| **Reproduce the results tables from shipped logs** | Python 3.10+ only. No Docker, no GPU, no API keys. This lives in the artifact repo (`sysrepair-artifact/`): run `./install.sh` there (the default, logs-only tier) and follow `claims/claimN/run.sh`. |
| **Re-run scenarios live** | Docker (and, for some suites, a Windows host with Hyper-V), the Inspect AI harness via `uv`, and a model provider — an API key or a local vLLM/Ollama endpoint. Detailed below. |

Everything below concerns running scenarios live from **this** repo.

## Execution backends

The benchmark spans **313 binary scenarios + 16 Hivestorm free-roam
scenarios** across three execution backends:

- **Linux containers** (ccdc, meta2, vulnhub, meta3/ubuntu, most of meta4,
  most of hivestorm) — run on a Linux Docker host.
- **Windows containers** (meta3/windows, hivestorm Windows scenarios) — run on
  a Windows host with Docker in *Windows containers* mode + Hyper-V isolation.
- **Hyper-V VMs** (meta4/ad-vm, meta4/kernel-vm, meta4/dirtypipe-vm,
  meta3/windows-vm, hivestorm scenarios 13 and 14) — run on a Windows host
  with Hyper-V, driven by the PowerShell scripts under each scenario's `lab/`
  directory.

> **There is no Vagrant, VirtualBox, or libvirt/KVM path.** The repo contains
> no Vagrantfiles; the former Vagrant/VirtualBox VMs were all ported to
> Hyper-V (see `meta4/kernel-vm/lab/hyperv.json`,
> `hivestorm/scenario-13-ad-dc-win2019/lab/automatedlab.json`, and
> `meta4/ad-vm/README.md`). Because every non-Linux backend now wants Hyper-V
> **on**, a single Windows machine can host all Windows containers *and* all
> VM-backed scenarios — the old "Hyper-V off for VirtualBox" host class is
> gone.

## Recommended host topology (2 hosts)

| Host | OS | Runs |
|---|---|---|
| **Host A — Linux Docker** | Ubuntu 22.04+ / Debian 12+ / Fedora 40+ | All Linux container suites; the Inspect AI harness; meta2 (requires a native Linux kernel for the Hardy `vsyscall` page) |
| **Host B — Windows + Hyper-V** | Windows 10/11 Pro or Enterprise (or Win Server 2019+), Hyper-V ON | meta3/windows (21) and hivestorm Windows containers (03, 04, 05, 08, 11); all Hyper-V VM labs: meta4/ad-vm (S01–S20), meta4/kernel-vm + meta4/dirtypipe-vm, meta3/windows-vm, hivestorm scenarios 13 and 14 |

If you only have one machine, see [Single-host fallbacks](#single-host-fallbacks).

### Recommended specs

| Host | CPU | RAM | Storage | Notes |
|---|---|---|---|---|
| **Host A** | 8 cores / 16 threads | 16 GB min, **32 GB recommended** | **200 GB SSD** | Docker layer cache + meta2 Hardy multi-stage build + ~250 container images grow fast under repeated runs. |
| **Host B** | 8 cores / 16 threads | 16 GB min, **32 GB recommended** | **250 GB SSD** | Windows Server Core ltsc2019 base is ~5 GB; the meta4/ad-vm lab wants ~10 GB free RAM and ~60 GB disk for its four VMs. |

### Suite → host mapping

| Suite | Host A (Linux+Docker) | Host B (Windows+Hyper-V) |
|---|:-:|:-:|
| `ccdc/` (50) | ✅ | |
| `meta2/` (40) | ✅ (native Linux only) | |
| `vulnhub/` (30) | ✅ | |
| `meta3/ubuntu/` (19) | ✅ | |
| `meta3/windows/` (21) | | ✅ Windows containers |
| `meta3/windows-vm/` (live-protocol ports of scenarios 10–12) | | ✅ Hyper-V VM |
| `meta4/` Docker (113 of 117) | ✅ | |
| `meta4/` kernel-coupled (S19, S21, S22, S117) | | ✅ Hyper-V Docker-host VMs (`kernel-vm/`, `dirtypipe-vm/`) |
| `meta4/ad-vm/` (S01–S20) | | ✅ Hyper-V + AutomatedLab |
| `hivestorm/` Linux (01, 02, 06, 07, 09, 10, 12, 15, 16) | ✅ | |
| `hivestorm/` Windows containers (03, 04, 05, 08, 11) | | ✅ Windows containers |
| `hivestorm/scenario-13-ad-dc-win2019` | | ✅ Hyper-V + AutomatedLab |
| `hivestorm/scenario-14-freebsd13` | | ✅ Hyper-V |

The Inspect AI harness can drive any backend; install it on whichever host
launches the runs. For VM-backed scenarios the harness shells out to
`powershell.exe` to restore/start the VM, so those runs must be launched on
the Hyper-V host itself; the agent then runs in a small Linux bridge container
that SSHes into the VM.

---

## Host A — Linux + Docker (the workhorse)

Covers every Linux container suite plus the Inspect AI harness. **meta2 must
run here** (Hardy's `vsyscall` page is unavailable on Docker Desktop / WSL2
kernels), and so must the sandbox-escape scenarios `meta4/scenario-70..72`
(Docker Desktop's seccomp profile makes their baseline verify pass
spuriously).

### A1. System prerequisites

Use your distro's package manager — never curl-install when an apt/dnf
package exists.

**Ubuntu 22.04+ / Debian 12+:**

```bash
sudo apt update
sudo apt install -y \
    git curl ca-certificates jq bash \
    docker.io docker-buildx \
    python3 python3-venv
sudo usermod -aG docker "$USER"   # log out / back in afterwards
```

**Fedora 40+ / RHEL 9+:**

```bash
sudo dnf install -y \
    git curl ca-certificates jq bash \
    docker docker-buildx \
    python3
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

Verify Docker can run rootless from your account:

```bash
docker run --rm hello-world
```

### A2. `uv` for the Inspect AI harness

`uv` manages the Python env and lockfile (the harness declares Python ≥ 3.11;
`uv sync` provisions its own interpreter). Use the official installer (no
distro package yet):

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
exec "$SHELL"   # reload PATH
```

### A3. Clone + harness install

```bash
git clone <repo-url> sysrepair-bench
cd sysrepair-bench/inspect_eval
uv sync           # creates .venv, installs Inspect AI + providers
cd ..
```

### A4. Pre-build the meta2 Hardy base (optional)

The harness builds it on first run, but you can pre-warm it:

```bash
docker build -t sysrepair/meta2-hardy:latest meta2/_base
```

### A5. Regenerate hivestorm identities (every run)

Hivestorm scenarios randomize backdoor accounts, trojan paths, SUID plants,
rogue crons, and the legit admin name at build time. **Run this before every
hivestorm session** (Linux *and* Windows containers — Host B reads the same
`build/roles.json`):

```bash
bash hivestorm/prepare.sh            # all 16 scenarios, random seed
SEED=42 bash hivestorm/prepare.sh    # reproducible
bash hivestorm/prepare.sh 01         # single scenario
```

On Windows hosts use the PowerShell port:

```powershell
pwsh hivestorm/prepare.ps1
```

### A6. Smoke test

The tracked `example.runs.yaml` ships the `smoke` preset with a placeholder
model (`openai/MODEL_NAME`), so it will not run as-is. Point it at a real
endpoint first. The launcher prefers `inspect_eval/runs.yaml` (gitignored) over
the tracked template, so the usual move is to copy it and edit the copy:

```bash
cd inspect_eval
cp example.runs.yaml runs.yaml
# in runs.yaml, set the smoke preset's `model:` (and `base_url:`/`api_key:` if
# you are serving locally) to the endpoint you want to test against
uv run python -m sysrepair_bench.run smoke
```

The smoke preset runs a single scenario (`meta2/scenario-01`) under ReAct and
exits. It is the fastest end-to-end check that Docker, the harness, the model
endpoint, and the scoring oracle are all wired together.

---

## Host B — Windows + Hyper-V

One Windows machine covers both remaining backends: Windows containers and
the Hyper-V VM labs. Hyper-V stays **on** for everything.

### B1. Enable Hyper-V + Containers

Elevated PowerShell:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
Enable-WindowsOptionalFeature -Online -FeatureName Containers -All -NoRestart
Restart-Computer
```

After reboot, confirm:

```powershell
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
Get-WindowsOptionalFeature -Online -FeatureName Containers
```

### B2. Tooling via Scoop

[Scoop](https://scoop.sh) is the package manager we use on Windows — it does
not need admin rights and pins versions cleanly.

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
irm get.scoop.sh | iex

scoop install git python uv jq
scoop bucket add extras
scoop install docker docker-compose
```

(Docker Desktop is also fine — install via its MSI if you prefer. Scoop's
`docker` package gives you the CLI + dockerd; pair with the Hyper-V backend.)

### B3. Windows containers (meta3/windows + hivestorm 03/04/05/08/11)

Switch Docker to Windows containers + Hyper-V isolation:

- **Docker Desktop:** right-click tray → *Switch to Windows containers*.
- **Native dockerd:** add `"exec-opts": ["isolation=hyperv"]` to
  `%ProgramData%\docker\config\daemon.json` and restart the Docker service.

The harness auto-injects `isolation: hyperv` for every Windows-container
scenario (`task.py` sets it whenever the scenario OS is Windows), so manual
flags are only needed for ad-hoc `docker run` outside the harness.

Then clone + install the harness and smoke-test:

```powershell
git clone <repo-url> sysrepair-bench
cd sysrepair-bench\inspect_eval
uv sync
docker run --rm mcr.microsoft.com/windows/servercore:ltsc2019 cmd /c ver
```

### B4. Kernel-coupled meta4 scenarios — Hyper-V Docker-host VMs

`meta4/scenario-19, -21, -22, -117` target kernel CVEs; containers share the
host kernel, so they run as **privileged containers inside a Hyper-V VM with
a pinned vulnerable kernel**:

- [`meta4/kernel-vm/`](meta4/kernel-vm/) — Ubuntu 22.04 pinned at
  `5.15.0-25-generic`, hosts S21 (GameOver(lay)), S22 (`nf_tables` UAF) and
  S117 (Copy Fail).
- [`meta4/dirtypipe-vm/`](meta4/dirtypipe-vm/) — Ubuntu 20.04 HWE pinned at
  `5.13.0-27-generic`, hosts S19 (Dirty Pipe), whose fix is already in
  5.15.0-25.

Requirements (see [`meta4/kernel-vm/README.md`](meta4/kernel-vm/README.md)):
Hyper-V, an **elevated** PowerShell, `qemu-img` (`scoop install qemu`), and
`oscdimg` from the Windows ADK Deployment Tools.

```powershell
cd meta4\kernel-vm\lab
. .\KernelLab.ps1
Install-KernelLab     # image -> VHDX -> cloud-init seed -> provision -> baseline checkpoint
```

At run time, a preset carrying `hyperv_vm: meta4/kernel-vm` (the legacy key
`vagrant_vm:` still works) makes `run.py` read `lab/hyperv.json`, bring the
VM up via `Initialize-KernelHost`, and point `DOCKER_CONTEXT` at the VM over
SSH so images build and run on the VM's vulnerable kernel. See the
`kernel_vm` preset in
[`inspect_eval/example.runs.yaml`](inspect_eval/example.runs.yaml); for the
Dirty Pipe VM use `hyperv_vm: meta4/dirtypipe-vm`.

All four scenarios also accept a host-kernel-agnostic **compensating
control** — see [`meta4/README.md`](meta4/README.md).

### B5. Hivestorm VM scenarios 13 (AD DC) and 14 (FreeBSD)

Both are Hyper-V VMs the harness drives through the entry points named in
each scenario's `lab/automatedlab.json`; the agent works from a Linux bridge
container that SSHes to the VM on a forwarded host port. Per-sample the
harness restores the baseline checkpoint, installs the bridge SSH key, and
sets up the port proxy itself — you only build the VM once:

- **scenario-13** (Windows Server 2019 AD DC): built by AutomatedLab —
  elevated PowerShell, run
  `hivestorm\scenario-13-ad-dc-win2019\lab\Hs13Lab.ps1`, then
  `Save-Hs13Baseline` (from `lab\Hs13Ops.ps1`) to capture the clean
  snapshot. Needs the AutomatedLab prerequisites from the AD-lab section
  below (module + Server 2019 evaluation ISO).
- **scenario-14** (FreeBSD 13.2): AutomatedLab has no FreeBSD support and the
  official image has no unattended install path, so the `hs14-bsd` VM was
  bootstrapped manually; `lab/Bsd14Ops.ps1` documents the process and
  provides all runtime operations (`Initialize-Hs14Host`,
  `Restore-Hs14Baseline`, …).

Run `bash hivestorm/prepare.sh 13` (or `14`) first, as with every hivestorm
scenario; then use the `win_vm` / `freebsd_vm` presets in
[`inspect_eval/example.runs.yaml`](inspect_eval/example.runs.yaml).

### B6. meta3/windows-vm — live SMB/RDP scenarios

Three `meta3/windows/` scenarios (10 SMBv1, 11 SMB signing, 12 RDP NLA) also
exist as VM-backed ports whose grading probes a **live** protocol listener a
Server-Core container cannot host. One AutomatedLab-built standalone Server
2019 VM (`META3WIN`); per-scenario inject on a restored baseline via
`meta3/windows-vm/run-scenario.sh NN`. See
[`meta3/windows-vm/README.md`](meta3/windows-vm/README.md).

### B7. The Active Directory lab (`meta4/ad-vm/`, 20 scenarios)

Runs `meta4/ad-vm/` — 20 Active Directory scenarios on a four-machine
Hyper-V lab (Win2019 DC + Enterprise CA + member workstation + Ubuntu
attacker VM carrying the Kali tooling container), built with AutomatedLab.
Every step below is elevated PowerShell unless noted. Versions are the ones
this was built and verified against. Full detail:
[`meta4/ad-vm/lab/RUNBOOK.md`](meta4/ad-vm/lab/RUNBOOK.md).

#### D1. Enable Hyper-V

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All
# reboot
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All | Select-Object State
# Expect: Enabled
```

Requires Windows 10/11 **Pro**, Enterprise or Education. Home does not ship
Hyper-V.

#### D2. PowerShell modules

```powershell
Install-Module Pester       -MinimumVersion 5.0.0 -Scope CurrentUser -Force -SkipPublisherCheck
Install-Module AutomatedLab -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck
```

Verified against **Pester 6.0.1** and **AutomatedLab 5.61.0**. Record the
AutomatedLab version in `meta4/ad-vm/lab/IMAGES.md` — the lab definition uses
its role API, which does change between majors.

#### D3. Windows ADK — Deployment Tools only

Provides `oscdimg`, used to build the cloud-init seed ISO for the attacker VM.

Download the ADK from
<https://learn.microsoft.com/windows-hardware/get-started/adk-install>, and in
the feature list **untick everything except "Deployment Tools"** — roughly a
100 MB install instead of several GB.

```powershell
# The ADK does not add oscdimg to PATH. Confirm it landed:
Get-ChildItem 'C:\Program Files (x86)\Windows Kits' -Recurse -Filter oscdimg.exe |
    Where-Object FullName -like '*amd64*' | Select-Object -ExpandProperty FullName
```

The harness locates it under Windows Kits automatically; you do not need to
add it to PATH.

#### D4. LabSources — create this BEFORE importing AutomatedLab

```powershell
$base = 'C:\LabSources'
foreach ($d in 'ISOs','OSUpdates','PostInstallationActivities','Tools',
                'SoftwarePackages','CustomRoles','LabScripts') {
    New-Item -ItemType Directory -Path (Join-Path $base $d) -Force | Out-Null
}
Import-Module AutomatedLab
Get-LabSourcesLocation      # Expect: C:\LabSources
```

**Order matters.** `Import-Module AutomatedLab` resolves its LabSources
location during import and fails with *"Cannot bind argument to parameter
'Path' because it is null"* when the folder is absent — so you cannot use
`New-LabSourcesFolder` to create it. `lab/SysRepairLab.ps1` does this for you;
the manual form is here for diagnosis.

#### D5. Installation media

Place both ISOs in `C:\LabSources\ISOs\`:

| ISO | Source | Size |
|---|---|---|
| Windows Server 2019 evaluation | <https://www.microsoft.com/evalcenter/download-windows-server-2019> — choose **ISO**, 64-bit English | ~5.3 GB |
| Ubuntu Server 24.04 LTS | <https://releases.ubuntu.com/24.04/> — `*-live-server-amd64.iso` | ~3.0 GB |

Then verify against the recorded hashes:

```powershell
cd meta4\ad-vm
. .\lab\Test-ImageChecksums.ps1
Test-ImageChecksums -ManifestPath .\lab\IMAGES.md -ImageDir 'C:\LabSources\ISOs'
```

If you obtained different builds, update `lab/IMAGES.md` with your own hashes
from `Get-ChildItem C:\LabSources\ISOs\*.iso | Get-FileHash -Algorithm SHA256`.

**Edition string.** `Install-Lab` exact-matches `-OperatingSystem`. The
evaluation media reports `Windows Server 2019 Datacenter Evaluation (Desktop
Experience)` — note *Evaluation*, which the retail spelling omits. Check yours:

```powershell
Get-LabAvailableOperatingSystem -Path C:\LabSources\ISOs |
    Select-Object OperatingSystemName, Version
```

and set `$osName` in `lab/SysRepairLab.ps1` to match. The script's preflight
prints the available list if it does not.

#### D6. Host WinRM remoting — read before running

AutomatedLab **requires** `TrustedHosts = '*'` and CredSSP delegation to
`WSMAN/*`. This is not configurable: `AutomatedLabCore.psm1` throws
*"TrustedHosts need to be set to '*' in order to be able to connect to the new
VMs"*, and a subnet-scoped TrustedHosts list does not satisfy its precheck.

Understand what this changes before accepting it:

- **`TrustedHosts = '*'`** — the host will authenticate to *any* WinRM endpoint
  over NTLM without mutual authentication.
- **CredSSP client auth with fresh-credential delegation to `WSMAN/*`** — your
  credentials can be delegated to any host you connect to.
- **`AllowEncryptionOracle = 2`** — this one is easy to miss because
  `Enable-LabHostRemoting` sets it without calling attention to it. It relaxes
  the CVE-2018-0886 CredSSP encryption-oracle mitigation to "Vulnerable",
  permitting CredSSP connections to unpatched servers. It is the most
  security-relevant of the three.

On a dedicated lab machine this is normal. On a machine you also use for other
work, weigh it.

```powershell
Enable-LabHostRemoting -Force
Test-LabHostRemoting          # Expect: True
```

To revert afterwards:

```powershell
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '' -Force
Set-Item WSMan:\localhost\Client\Auth\CredSSP -Value $false -Force
Remove-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Recurse -Force
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' `
                    -Name 'AllowEncryptionOracle' -ErrorAction SilentlyContinue
gpupdate /force
```

Per-scenario runs do **not** need any of this: `Invoke-Scenario.ps1` reaches
the guests over PowerShell Direct (VMBus), which needs no network path and no
TrustedHosts entry. Only `Install-Lab` and the initial provisioning require it,
so reverting after the baseline is captured is viable.

#### D7. Docker, for the attacker tooling image

Docker Desktop in **Linux containers** mode. Verified against 29.4.0.

```powershell
cd meta4\ad-vm
docker build -t srb-attacker:1 .\lab\attacker
# Expect: tool gate: all 16 scenario dependencies resolve AND execute
```

The build fails loudly if any tool a `verify-poc.sh` invokes is missing or
cannot run. That gate is deliberate — a missing grader tool used to be graded
as "attack blocked", i.e. a pass on a vulnerable box.

#### D8. Virtual switches

```powershell
cd meta4\ad-vm
. .\lab\New-LabSwitches.ps1

# Internal switches only, if the host's sole live adapter is the one you are
# working over -- creating an External switch on it briefly drops connectivity.
New-LabSwitches -SkipExternal

Get-LabSwitchHealth      # SRB-Lab 10.20.30.1, SRB-Kernel 10.20.40.1, both Private
Test-NoLabNatCollision   # Hyper-V allows one NAT prefix per host; WSL2 usually owns it
```

`SRB-Build` (External) is only needed while baking the attacker VM. Create it
then, naming the adapter explicitly:

```powershell
Get-NetAdapter -Physical | Where-Object Status -eq 'Up'
New-LabSwitches -ExternalAdapterName '<adapter>'
```

#### D9. Build the lab

```powershell
cd meta4\ad-vm
powershell -ExecutionPolicy Bypass -File .\lab\SysRepairLab.ps1   # 45-90 min

. .\lab\Protect-ParentDisk.ps1
Set-LabVMHardening -VMName corp-dc01,corp-ca01,corp-ws01
Protect-ParentDisk -ParentVhdxPath (Get-LabParentDiskPath -VMName corp-dc01)
```

`Set-LabVMHardening` is not optional. It disables automatic checkpoints — which
client Hyper-V takes on *every VM start*, reintroducing exactly the live-state
DC snapshot the cold-baseline model exists to avoid — switches checkpoint type
to Standard, and pins fixed memory on the DC and attacker.

#### D10. Attacker VM

```powershell
. .\lab\New-AttackerVM.ps1

New-AttackerSshKey                       # host-side probes use key auth, not passwords
New-CloudInitSeedIso -CloudInitDir .\lab\attacker\cloud-init -OutputIsoPath C:\srb\seed.iso
New-AttackerVM -UbuntuIsoPath C:\LabSources\ISOs\ubuntu-24.04.2-live-server-amd64.iso `
               -VhdxPath      C:\srb\attacker01.vhdx `
               -SeedIsoPath   C:\srb\seed.iso

Start-VM attacker01
# Complete the Ubuntu install. The VM sits on SRB-Build (internet) on purpose:
# cloud-init installs docker.io. Note its DHCP address from the console.

Install-AttackerTooling -BuildHost <dhcp-address>
Move-AttackerToLabNetwork
Start-VM attacker01
```

#### D11. Provision, baseline, verify

```powershell
$cred = New-Object System.Management.Automation.PSCredential('CORP\Administrator',
    (ConvertTo-SecureString 'Password1!' -AsPlainText -Force))

Invoke-Command -VMName corp-dc01 -Credential $cred -FilePath .\provision\seed-directory.ps1
Invoke-Command -VMName corp-ca01 -Credential $cred -FilePath .\provision\ca-postinstall.ps1

Import-Module .\lab\LabReadiness.psm1 -Force
. .\lab\Start-LabOrdered.ps1
. .\lab\Save-LabBaseline.ps1
. .\lab\Test-LabEgress.ps1

Start-LabOrdered      # ordered boot, clocks verified
Test-LabEgress        # must confirm NO internet reachable from attacker01
Save-LabBaseline      # atomic across all four machines

Invoke-Pester .\tests -Output Detailed
```

#### D12. Run a scenario

```bash
./run-scenario.sh 13                    # restore -> inject -> handoff
./run-scenario.sh 13 --verify-only      # grade; exits 0 iff both gates pass
```

#### Known gotchas

| Symptom | Cause |
|---|---|
| `Import-Module AutomatedLab` throws *"Cannot bind argument to parameter 'Path'"* | `C:\LabSources` does not exist. See D4 — create it first. |
| `Install-Lab`: *"could not be found in the available operating systems"* | `$osName` does not exactly match the ISO's edition string. See D5. |
| `Install-Lab` dies with *"PromptForChoice ... Object reference not set"* | AutomatedLab is trying to prompt from a non-interactive host. Run `Enable-LabHostRemoting -Force` first (D6). |
| `New-CloudInitSeedIso`: *"oscdimg.exe not found"* | ADK Deployment Tools not installed, or installed without that feature. See D3. |
| Attacker VM boots with no SSH key and no static IP; every probe times out | Seed ISO built without Joliet, so cloud-init saw `USER-DATA` rather than `user-data`. The harness passes `-j1`; if building by hand, do the same. |
| `docker build` fails at the tool gate | A tool some `verify-poc.sh` invokes is missing. That is the gate working — fix the image, do not remove the check. |
| certipy fails with `ept_s_not_registered` for `91AE6020-9E3C-11CF-8D7C-00AA00C091BE`, yet `certutil -ping` on corp-ca01 succeeds and the CA still issues certificates locally | CertSvc registers its RPC endpoints **once, at service start**. Resuming a snapshot can start it before the network is up, so it binds `ncalrpc` only and never advertises a TCP endpoint. Every check *on* the CA stays green; nothing else in the lab can reach it. Waiting does not help — restart CertSvc (`Repair-CaRpcEndpoint`). `Start-LabOrdered` now detects and repairs this automatically. |

---

## Model provider credentials

The harness needs at least one provider. Set env vars on whichever host runs
the harness:

| Provider | Env var(s) |
|---|---|
| OpenAI / OpenAI-compatible (vLLM, Ollama, LM Studio) | `OPENAI_API_KEY` (any non-empty string for local), optionally `OPENAI_BASE_URL` |
| Anthropic | `ANTHROPIC_API_KEY` |
| Google Gemini | `GOOGLE_API_KEY` |
| Hugging Face Inference | `HF_TOKEN` |

Drop them into `inspect_eval/.env` (auto-loaded by the run script).

Reproducing tables from the shipped artifact logs needs **no** credentials.

---

## Single-host fallbacks

If you only have one machine, you can still run a meaningful subset:

- **Linux only:** all Linux container suites (`ccdc`, `meta2`, `vulnhub`,
  `meta3/ubuntu`, 113 of the 117 `meta4` Docker scenarios, 9 hivestorm Linux
  scenarios). You **cannot** run the Windows containers (they need a Windows
  kernel) or any Hyper-V VM lab (Hyper-V is Windows-only) — there is no
  VM-on-Linux workflow.
- **Windows only (Hyper-V ON):** Windows containers, all VM labs, and Linux
  containers via Docker Desktop's WSL2 backend — **except** `meta2/`
  (needs the legacy `vsyscall` page, absent from the WSL2 kernel) and the
  sandbox-escape scenarios `meta4/scenario-70..72` (Docker Desktop's seccomp
  profile defeats their baseline PoC).

---

## Verification checklist

Run these on each host once setup is complete:

| Host | Check | Expected |
|---|---|---|
| A | `docker run --rm hello-world` | `Hello from Docker!` |
| A | `cd inspect_eval && uv run python -m sysrepair_bench.run smoke` | one scenario passes verify |
| B | `docker run --rm mcr.microsoft.com/windows/servercore:ltsc2019 cmd /c ver` | Windows version banner |
| B | `Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All` | `Enabled` |
| B (kernel VMs) | `. meta4\kernel-vm\lab\KernelOps.ps1; Initialize-KernelHost` | restore, start, port proxy, ABI check all pass |
