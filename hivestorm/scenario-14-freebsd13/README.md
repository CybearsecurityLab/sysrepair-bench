# scenario-14-freebsd13 — divergent invocation

Unlike the Docker-native scenarios, this one is a **Hyper-V VM**: FreeBSD
cannot run inside a Linux container (different kernel ABI, `pf` lives in
the kernel, `kldload` requires a real kernel, `rc.d` expects the FreeBSD
init). The former Vagrant/VirtualBox path has been retired.

## Prereqs

- Windows host with Hyper-V enabled; **elevated** PowerShell
- The `hs14-bsd` VM. AutomatedLab has no FreeBSD support and the official
  FreeBSD 13.2 image has no unattended install path (no cloud-init, no
  serial console, sshd disabled), so the VM was bootstrapped manually by
  injecting keystrokes into the video console; the process, and everything
  it left in place, is documented at the top of `lab/Bsd14Ops.ps1`.

## Build flow

```powershell
# 1. Generate roles.json + render task.md (same as Docker scenarios)
bash hivestorm/prepare.sh 14     # or: pwsh hivestorm/prepare.ps1 14

# 2. Restore + start + port proxy + reachability check, in one call
cd hivestorm\scenario-14-freebsd13
. .\lab\Bsd14Ops.ps1
Initialize-Hs14Host
```

At eval time no manual bring-up is needed: `task.py` reads
`lab/automatedlab.json` and drives the same functions itself; the agent runs
in a Linux bridge container and SSHes to the VM as `root` on
`host.docker.internal:2222`. The baseline checkpoint was taken after
`seed.sh` ran and was erased from the VM, so a restore returns the box to
exactly the state a graded run starts from.

## Running the verifier

There is no standing verifier on the VM: at scoring time the harness
(`scorer.py`) uploads `verify.sh` and re-uploads `roles.json` (erased from
the VM after seeding) over the bridge SSH session, runs the check, and
removes them again. Root's shell is tcsh, so remote commands are wrapped in
`sh -c`. JSONL output is captured and scored by `hivestorm_weighted_scorer`.

## Scope caveats

- **FreeBSD-specific toolchain only.** `pf`, `rc.conf`, `kldstat`,
  `periodic`, `pkg audit` are the primitives the agent must know. A
  Linux-centric approach (iptables, systemctl, apt) will fail.
- **pkg audit** runs against the live vulnxml feed. The seeder installs
  a deliberately old `rogue_pkg` name — the agent is credited for either
  removing it or for upgrading it via `pkg upgrade`.
- **No ZFS** requirements. The box defaults to UFS; ZFS-specific
  hardening (dataset ACLs, snapshots) is out of scope for this scenario.
