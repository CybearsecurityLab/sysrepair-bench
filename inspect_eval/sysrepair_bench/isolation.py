"""Keep agent processes away from the grader, and regrade passes on a clone.

Two mechanisms, both driven from the HOST through the Docker CLI:

1. Agent-process stop hook (in place).
   At boot, before the agent's first action, the harness records every process
   in the episode container (PID, kernel start time, executable, command line)
   and every listening socket. Before each grading it suspends (SIGSTOP) every
   process that is not in that record, and resumes (SIGCONT) them afterwards,
   so nothing the agent left running can watch for, copy, or rewrite the
   verifier while it exists. Services are excluded from the stop: processes in
   the boot record, plus any process holding a socket that a boot-time process
   listened on, so a service the agent restarted stays reachable for the
   regression checks.

2. Clone regrade.
   After an in-place pass, the container's filesystem is committed to an image
   and booted as a fresh container on an internal network. No agent process
   ever ran in it. Processes the agent arranged to autostart (a cron entry, a
   modified start script) do run at boot, so the clone's stop hook matches by
   identity (executable + command line) against the ORIGINAL boot record and
   suspends everything else. The verifier then runs in the clone.

Everything that runs inside a container to observe or signal processes is a
STATIC busybox copied in from the host and invoked by absolute path, so a
shimmed /bin/sh, ps or kill inside the container cannot falsify the process
table the host reasons about. The host decides what to stop; busybox only
reports /proc and delivers signals, and every signal is re-checked against the
target's kernel start time so a recycled PID is never signalled.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

BUSYBOX = os.environ.get("SR_STATIC_BUSYBOX", shutil.which("busybox") or "/usr/bin/busybox")
CLONE_READY_TIMEOUT_S = float(os.environ.get("SR_CLONE_READY_TIMEOUT_S", "240"))
CLONE_SETTLE_S = float(os.environ.get("SR_CLONE_SETTLE_S", "8"))
VERIFY_TIMEOUT_S = 360
MAX_STOP_ROUNDS = 6

# Busybox ash. $0 is the busybox path. Prints one record per line:
#   P|pid|starttime|state|ppid|exe|cmdline
#   F|pid|socket-inode
#   L|tcp:PORT|inode   (LISTEN), udp:PORT (bound), unix:PATH (listening)
#   S|helper-pid
_SNAPSHOT_SH = r'''
BB="$0"; SELF=$$
for d in /proc/[0-9]*; do
  p=${d#/proc/}
  s=$("$BB" cat "$d/stat" 2>/dev/null) || continue
  [ -n "$s" ] || continue
  rest=${s##*\)}
  set -- $rest
  st=$1; pp=$2; start=${20}
  exe=$("$BB" readlink "$d/exe" 2>/dev/null)
  cmd=$("$BB" tr '\000|\n' ' ;;' < "$d/cmdline" 2>/dev/null | "$BB" head -c 400)
  echo "P|$p|$start|$st|$pp|$exe|$cmd"
  for f in "$d"/fd/*; do
    l=$("$BB" readlink "$f" 2>/dev/null) || continue
    case "$l" in socket:\[*\]) i=${l#socket:[}; echo "F|$p|${i%]}";; esac
  done
done
"$BB" awk 'FNR>1 && $4=="0A" {n=split($2,a,":"); print "L|tcp:" a[n] "|" $10}' /proc/net/tcp /proc/net/tcp6 2>/dev/null
"$BB" awk 'FNR>1 && $4=="07" {n=split($2,a,":"); print "L|udp:" a[n] "|" $10}' /proc/net/udp /proc/net/udp6 2>/dev/null
"$BB" awk 'FNR>1 && $4=="00010000" && NF>=8 {print "L|unix:" $8 "|" $7}' /proc/net/unix 2>/dev/null
echo "S|$SELF"
'''

# Signal each "pid:start" argument only if the PID still has that start time.
# $1 is the signal name (STOP or CONT).
_SIGNAL_SH = r'''
BB="$0"; sig="$1"; shift
for ps in "$@"; do
  p=${ps%%:*}; want=${ps#*:}
  s=$("$BB" cat "/proc/$p/stat" 2>/dev/null) || { echo "GONE|$p"; continue; }
  rest=${s##*\)}
  set -- $rest
  if [ "${20}" = "$want" ]; then
    kill -s "$sig" "$p" 2>/dev/null && echo "OK|$p" || echo "ERR|$p"
  else
    echo "REUSED|$p"
  fi
done
'''


# --------------------------------------------------------------------------
# Docker plumbing
# --------------------------------------------------------------------------

async def _run(argv: list[str], timeout: float = 120, input: bytes | None = None
               ) -> tuple[int, bytes, bytes]:
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE if input is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(input), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, b"", f"timed out after {timeout}s: {argv[:3]}".encode()
    return proc.returncode, out, err


async def _install_helper(cid: str) -> str:
    """Copy the host's static busybox into the container under a random
    directory. The file must be NAMED busybox: busybox picks the applet from
    argv[0] unless its own name is busybox."""
    d = f"/.sr-bb-{uuid.uuid4().hex[:12]}"
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "h"
        src.mkdir()
        shutil.copy2(BUSYBOX, src / "busybox")
        os.chmod(src, 0o700)
        rc, _o, err = await _run(["docker", "cp", str(src), f"{cid}:{d}"], timeout=60)
    if rc != 0:
        raise RuntimeError(f"docker cp busybox failed: {err.decode(errors='replace')[:200]}")
    return f"{d}/busybox"


async def _remove_helper(cid: str, helper: str | None) -> None:
    if helper:
        d = str(Path(helper).parent)
        await _run(["docker", "exec", "-u", "0", cid, helper, "rm", "-rf", d], timeout=30)


async def _bb_sh(cid: str, helper: str, script: str, *args: str, timeout: float = 60
                 ) -> tuple[int, str, str]:
    rc, out, err = await _run(
        ["docker", "exec", "-u", "0", cid, helper, "sh", "-c", script, helper, *args],
        timeout=timeout)
    return rc, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


async def read_file_host(cid: str, path: str) -> bytes | None:
    """A file's bytes via `docker cp` (a daemon-side tar stream). Nothing runs
    inside the container, so nothing the agent controls can alter the read."""
    rc, out, _err = await _run(["docker", "cp", f"{cid}:{path}", "-"], timeout=60)
    if rc != 0:
        return None
    try:
        with tarfile.open(fileobj=io.BytesIO(out)) as tf:
            for m in tf.getmembers():
                if m.isfile():
                    f = tf.extractfile(m)
                    return f.read() if f else None
    except tarfile.TarError:
        return None
    return None


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# --------------------------------------------------------------------------
# Process snapshots and the stop decision (pure, unit-tested)
# --------------------------------------------------------------------------

@dataclass
class Proc:
    pid: int
    start: str
    state: str
    ppid: int
    exe: str
    cmd: str

    @property
    def key(self) -> str:
        return f"{self.pid}:{self.start}"

    @property
    def ident(self) -> str:
        """Identity that survives a reboot of the same filesystem."""
        return f"{self.exe}|{self.cmd.strip()}"


@dataclass
class Snapshot:
    procs: dict[int, Proc] = field(default_factory=dict)
    fds: dict[int, set[str]] = field(default_factory=dict)
    listen: dict[str, set[str]] = field(default_factory=dict)  # key -> inodes
    helper_pid: int | None = None


def parse_snapshot(text: str) -> Snapshot:
    snap = Snapshot()
    for line in text.splitlines():
        parts = line.split("|")
        tag = parts[0]
        try:
            if tag == "P" and len(parts) >= 7:
                pid = int(parts[1])
                snap.procs[pid] = Proc(pid, parts[2], parts[3], int(parts[4] or 0),
                                       parts[5], "|".join(parts[6:]))
            elif tag == "F" and len(parts) == 3:
                snap.fds.setdefault(int(parts[1]), set()).add(parts[2])
            elif tag == "L" and len(parts) == 3:
                snap.listen.setdefault(parts[1], set()).add(parts[2])
            elif tag == "S" and len(parts) == 2:
                snap.helper_pid = int(parts[1])
        except ValueError:
            continue
    return snap


def boot_record_from(snap: Snapshot) -> dict:
    helper = _helper_tree(snap)
    procs = [p for p in snap.procs.values() if p.pid not in helper]
    return {
        "procs": sorted(p.key for p in procs),
        # With multiplicity: a clone may run as many processes of an identity
        # as the boot did, and no more (a loop the agent planted in a boot
        # script forks with that script's command line).
        "idents": sorted(p.ident for p in procs),
        "listen": sorted(snap.listen),
    }


def _helper_tree(snap: Snapshot) -> set[int]:
    """The helper shell and everything it forked for the snapshot."""
    if snap.helper_pid is None:
        return set()
    tree = {snap.helper_pid}
    changed = True
    while changed:
        changed = False
        for p in snap.procs.values():
            if p.pid not in tree and p.ppid in tree:
                tree.add(p.pid)
                changed = True
    return tree


def plan_stop(boot: dict, snap: Snapshot, mode: str = "inplace"
              ) -> tuple[list[Proc], list[Proc], list[Proc]]:
    """(to_stop, exempt_services, already_stopped).

    mode="inplace": a process is in the boot record iff its (pid, start time)
    is. mode="clone": PIDs differ after a reboot, so match by identity
    (executable + command line) against the original boot record.

    A process outside the record is exempt when it holds a socket on a key
    (tcp:PORT, udp:PORT, unix:PATH) that a boot-time process listened on: that
    is a service the agent restarted. Everything else outside the record is an
    agent process and is stopped. PID 1 is never stopped.
    """
    from collections import Counter
    boot_keys = set(boot.get("procs", []))
    quota = Counter(boot.get("idents", []))
    boot_listen = set(boot.get("listen", []))
    service_inodes: set[str] = set()
    for key, inodes in snap.listen.items():
        if key in boot_listen:
            service_inodes |= inodes
    helper = _helper_tree(snap)
    to_stop, exempt, stopped = [], [], []

    def _start(p: Proc) -> int:
        try:
            return int(p.start)
        except ValueError:
            return 0

    # Earliest-started first, so in a clone the boot-time instances of an
    # identity consume its quota before anything started later.
    for p in sorted(snap.procs.values(), key=lambda x: (_start(x), x.pid)):
        if p.pid == 1 or p.pid in helper:
            continue
        if p.state == "Z":
            continue
        if snap.fds.get(p.pid, set()) & service_inodes:
            if mode == "inplace" and p.key in boot_keys:
                continue
            if mode == "clone" and quota[p.ident] > 0:
                quota[p.ident] -= 1
                continue
            exempt.append(p)
            continue
        if mode == "inplace":
            if p.key in boot_keys:
                continue
        elif quota[p.ident] > 0:
            quota[p.ident] -= 1
            continue
        if p.state in ("T", "t"):
            stopped.append(p)
            continue
        to_stop.append(p)
    # A service's own forked helpers (smbd's notifyd and cleanupd, a
    # pre-fork pool) run the same executable and descend from it but may hold
    # no listening socket. Exempt a process when an exempt ancestor runs the
    # same executable; anything that exec'd something else stays stopped.
    exempt_pids = {p.pid: p for p in exempt}
    moved = True
    while moved:
        moved = False
        for p in list(to_stop):
            anc = snap.procs.get(p.ppid)
            seen = set()
            while anc is not None and anc.pid not in seen:
                seen.add(anc.pid)
                if anc.pid in exempt_pids and anc.exe and anc.exe == p.exe:
                    to_stop.remove(p)
                    exempt.append(p)
                    exempt_pids[p.pid] = p
                    moved = True
                    break
                anc = snap.procs.get(anc.ppid)
    return to_stop, exempt, stopped


# --------------------------------------------------------------------------
# Boot record, suspend, resume
# --------------------------------------------------------------------------

async def snapshot(cid: str, helper: str) -> Snapshot:
    rc, out, err = await _bb_sh(cid, helper, _SNAPSHOT_SH, timeout=90)
    if rc != 0 and not out:
        raise RuntimeError(f"process snapshot failed: {err[:200]}")
    return parse_snapshot(out)


async def capture_boot_record(cid: str) -> dict:
    helper = await _install_helper(cid)
    try:
        snap = await snapshot(cid, helper)
        rec = boot_record_from(snap)
        if not rec["procs"]:
            raise RuntimeError("empty process table")
        return rec
    finally:
        await _remove_helper(cid, helper)


@dataclass
class Suspension:
    cid: str
    helper: str | None = None
    stopped: list[Proc] = field(default_factory=list)
    exempt: list[Proc] = field(default_factory=list)
    preexisting: list[Proc] = field(default_factory=list)
    rounds: int = 0
    error: str | None = None
    resumed: int = 0

    def summary(self) -> dict:
        def brief(ps):
            return [f"{p.pid} {p.exe or '?'} {p.cmd[:80]}".strip() for p in ps]
        return {
            "status": "error" if self.error else "ok",
            "error": self.error,
            "stopped": brief(self.stopped),
            "exempt_services": brief(self.exempt),
            "already_stopped_by_agent": brief(self.preexisting),
            "rounds": self.rounds,
            "resumed": self.resumed,
        }


async def suspend_agent_processes(cid: str, boot: dict, mode: str = "inplace"
                                  ) -> Suspension:
    """SIGSTOP every non-service process outside the boot record.

    Repeats until a round finds nothing new to stop, so a process forked by a
    stopping parent between the snapshot and the signal is caught next round.
    """
    sus = Suspension(cid)
    try:
        sus.helper = await _install_helper(cid)
        seen_exempt: dict[str, Proc] = {}
        seen_pre: dict[str, Proc] = {}
        stopped: dict[str, Proc] = {}
        for _ in range(MAX_STOP_ROUNDS):
            sus.rounds += 1
            snap = await snapshot(cid, sus.helper)
            to_stop, exempt, pre = plan_stop(boot, snap, mode)
            for p in exempt:
                seen_exempt[p.key] = p
            for p in pre:
                if p.key not in stopped:
                    seen_pre[p.key] = p
            to_stop = [p for p in to_stop if p.key not in stopped]
            if not to_stop:
                break
            _rc, out, _err = await _bb_sh(cid, sus.helper, _SIGNAL_SH, "STOP",
                                          *[p.key for p in to_stop])
            ok = {int(l.split("|")[1]) for l in out.splitlines() if l.startswith("OK|")}
            for p in to_stop:
                if p.pid in ok:
                    stopped[p.key] = p
        else:
            sus.error = f"process table still changing after {MAX_STOP_ROUNDS} rounds"
        sus.stopped = list(stopped.values())
        sus.exempt = list(seen_exempt.values())
        sus.preexisting = list(seen_pre.values())
    except Exception as e:  # noqa: BLE001 -- recorded on the verdict
        sus.error = f"{type(e).__name__}: {e}"[:300]
    return sus


async def resume_agent_processes(sus: Suspension | None) -> None:
    if sus is None:
        return
    try:
        if sus.stopped and sus.helper:
            _rc, out, _err = await _bb_sh(sus.cid, sus.helper, _SIGNAL_SH, "CONT",
                                          *[p.key for p in sus.stopped])
            sus.resumed = sum(1 for l in out.splitlines() if l.startswith("OK|"))
    finally:
        await _remove_helper(sus.cid, sus.helper)
        sus.helper = None


# --------------------------------------------------------------------------
# Verifier delivery with host-side hash checks
# --------------------------------------------------------------------------

async def write_file_host(cid: str, path: str, data: bytes, mode: int = 0o700) -> None:
    """Write via `docker cp` from a host temp file (no shell in the container)."""
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / Path(path).name
        src.write_bytes(data)
        os.chmod(src, mode)
        rc, _o, err = await _run(["docker", "cp", str(src), f"{cid}:{path}"], timeout=60)
    if rc != 0:
        raise RuntimeError(f"docker cp failed: {err.decode(errors='replace')[:200]}")


# --------------------------------------------------------------------------
# Clone regrade
# --------------------------------------------------------------------------

def _create_args(info: dict, name: str, network: str) -> list[str]:
    """`docker create` flags that reproduce the episode container's runtime
    settings. Entrypoint, command, env, user and workdir travel in the
    committed image's config, so only host-config settings are copied."""
    hc = info.get("HostConfig") or {}
    cfg = info.get("Config") or {}
    args = ["docker", "create", "--name", name, "--network", network]
    if cfg.get("Hostname"):
        args += ["--hostname", cfg["Hostname"]]
    if hc.get("Privileged"):
        args.append("--privileged")
    for c in hc.get("CapAdd") or []:
        args += ["--cap-add", c]
    for c in hc.get("CapDrop") or []:
        args += ["--cap-drop", c]
    for s in hc.get("SecurityOpt") or []:
        args += ["--security-opt", s]
    if hc.get("CgroupnsMode"):
        args += ["--cgroupns", hc["CgroupnsMode"]]
    for path, opts in (hc.get("Tmpfs") or {}).items():
        args += ["--tmpfs", f"{path}:{opts}" if opts else path]
    for h in hc.get("ExtraHosts") or []:
        args += ["--add-host", h]
    if hc.get("ShmSize"):
        args += ["--shm-size", str(hc["ShmSize"])]
    if hc.get("Init"):
        args.append("--init")
    return args


async def _copy_volume(src_cid: str, dst_cid: str, dest: str) -> str | None:
    """Copy one volume's content from the episode container into the clone.
    Volumes are not part of `docker commit`, so without this a database or
    data directory would revert to its image state."""
    parent = str(Path(dest).parent) or "/"
    p1 = await asyncio.create_subprocess_exec(
        "docker", "cp", f"{src_cid}:{dest}", "-",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    data, err = await p1.communicate()
    if p1.returncode != 0:
        return f"read {dest}: {err.decode(errors='replace')[:120]}"
    rc, _o, err2 = await _run(["docker", "cp", "-", f"{dst_cid}:{parent}"],
                              timeout=600, input=data)
    if rc != 0:
        return f"write {dest}: {err2.decode(errors='replace')[:120]}"
    return None


async def _wait_ready(cid: str, ready_cmd: str | None) -> str | None:
    """None when ready; otherwise why not."""
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    if not ready_cmd:
        await asyncio.sleep(CLONE_SETTLE_S)
        rc, out, _ = await _run(["docker", "inspect", "-f", "{{.State.Running}}", cid])
        return None if out.strip() == b"true" else "clone exited during boot"
    while loop.time() - t0 < CLONE_READY_TIMEOUT_S:
        rc, _o, _e = await _run(["docker", "exec", cid, "sh", "-c", ready_cmd], timeout=60)
        if rc == 0:
            return None
        await asyncio.sleep(3)
    return f"clone not ready within {CLONE_READY_TIMEOUT_S:.0f}s"


async def clone_regrade(cid: str, verify_src: str, boot: dict | None,
                        ready_cmd: str | None, parse_summary) -> dict:
    """Grade a fresh boot of the episode container's final filesystem.

    Returns {"status": "pass"|"fail"|"unavailable", ...}. "unavailable" means
    the clone could not be built or booted, which is not a verdict."""
    tag = uuid.uuid4().hex[:12]
    image = f"sr-clone:{tag}"
    name = f"sr-clone-{tag}"
    network = f"sr-clone-{tag}"
    out: dict = {"status": "unavailable"}
    created = net_made = img_made = False
    sus: Suspension | None = None
    try:
        rc, info_raw, err = await _run(["docker", "inspect", cid])
        if rc != 0:
            out["reason"] = f"inspect: {err.decode(errors='replace')[:150]}"
            return out
        info = json.loads(info_raw)[0]
        rc, _o, err = await _run(["docker", "commit", cid, image], timeout=900)
        if rc != 0:
            out["reason"] = f"commit: {err.decode(errors='replace')[:150]}"
            return out
        img_made = True
        rc, _o, err = await _run(["docker", "network", "create", "--internal", network])
        if rc != 0:
            out["reason"] = f"network: {err.decode(errors='replace')[:150]}"
            return out
        net_made = True
        rc, _o, err = await _run(_create_args(info, name, network) + [image])
        if rc != 0:
            out["reason"] = f"create: {err.decode(errors='replace')[:150]}"
            return out
        created = True
        vol_errors = []
        for m in info.get("Mounts") or []:
            if m.get("Type") == "volume" and m.get("Destination"):
                e = await _copy_volume(cid, name, m["Destination"])
                if e:
                    vol_errors.append(e)
            elif m.get("Type") == "bind":
                out.setdefault("bind_mounts_not_copied", []).append(m.get("Destination"))
        if vol_errors:
            out["volume_copy_errors"] = vol_errors
        rc, _o, err = await _run(["docker", "start", name])
        if rc != 0:
            out["reason"] = f"start: {err.decode(errors='replace')[:150]}"
            return out
        why = await _wait_ready(name, ready_cmd)
        if why:
            out["reason"] = why
            return out
        if boot:
            sus = await suspend_agent_processes(name, boot, mode="clone")
            out["isolation"] = sus.summary()
            if sus.error:
                out["reason"] = f"clone stop hook: {sus.error}"
                return out
        else:
            out["isolation"] = {"status": "no boot record"}
        data = verify_src.encode()
        remote = f"/tmp/.sysrepair-verify-{uuid.uuid4().hex}.sh"
        await write_file_host(name, remote, data)
        before = await read_file_host(name, remote)
        if before is None or sha256(before) != sha256(data):
            out["status"] = "fail"
            out["reason"] = "verifier altered before it ran"
            return out
        rc, vout, verr = await _run(
            ["docker", "exec", name, "sh", "-c",
             'if command -v bash >/dev/null 2>&1; then exec bash "$0"; else exec sh "$0"; fi',
             remote], timeout=VERIFY_TIMEOUT_S)
        after = await read_file_host(name, remote)
        stdout = vout.decode("utf-8", "replace")
        summary = parse_summary(stdout)
        out["returncode"] = rc
        out["security_pass"] = summary.get("security_pass") if summary else None
        out["regression_pass"] = summary.get("regression_pass") if summary else None
        if after is None or sha256(after) != sha256(data):
            out["status"] = "fail"
            out["reason"] = "verifier altered while it ran"
        elif summary is None:
            out["status"] = "fail"
            out["reason"] = "no verdict summary"
        else:
            out["status"] = "pass" if rc == 0 else "fail"
        out["explanation_tail"] = (stdout + verr.decode("utf-8", "replace"))[-1500:]
        return out
    except Exception as e:  # noqa: BLE001 -- recorded as unavailable
        out["status"] = "unavailable"
        out["reason"] = f"{type(e).__name__}: {e}"[:300]
        return out
    finally:
        if sus is not None:
            await _remove_helper(name, sus.helper)
        if created:
            await _run(["docker", "rm", "-f", "-v", name], timeout=120)
        if net_made:
            await _run(["docker", "network", "rm", network], timeout=60)
        if img_made:
            await _run(["docker", "rmi", "-f", image], timeout=120)


def busybox_is_static(path: str = BUSYBOX) -> bool:
    try:
        out = subprocess.run(["file", "-L", path], capture_output=True, text=True,
                             timeout=10).stdout
        return "statically linked" in out
    except Exception:  # noqa: BLE001
        return False
