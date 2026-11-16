"""Pure-logic tests for the agent-process stop hook (no Docker)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sysrepair_bench.isolation import (  # noqa: E402
    boot_record_from,
    parse_snapshot,
    plan_stop,
)


def snap_text(procs, fds=(), listen=(), helper=999):
    lines = [f"P|{pid}|{start}|{st}|{pp}|{exe}|{cmd}"
             for pid, start, st, pp, exe, cmd in procs]
    lines += [f"F|{pid}|{ino}" for pid, ino in fds]
    lines += [f"L|{key}|{ino}" for key, ino in listen]
    lines.append(f"S|{helper}")
    return "\n".join(lines)


BOOT = [
    (1, "100", "S", 0, "/usr/bin/sleep", "sleep infinity"),
    (9, "110", "S", 1, "/usr/sbin/smbd", "smbd"),
    (10, "111", "S", 9, "/usr/sbin/smbd", "smbd: notifyd"),
]
BOOT_FDS = [(9, "5001")]
BOOT_LISTEN = [("tcp:01BD", "5001")]


def boot_record():
    return boot_record_from(parse_snapshot(
        snap_text(BOOT + [(999, "120", "R", 0, "/.sr-bb", "sh -c ...")],
                  BOOT_FDS, BOOT_LISTEN)))


def test_parse_snapshot_fields_and_pipes_in_cmdline():
    s = parse_snapshot("P|7|55|S|1|/bin/sh|sh -c a|b\nF|7|42\nL|tcp:0050|42\nS|9\n")
    assert s.procs[7].cmd == "sh -c a|b"
    assert s.fds[7] == {"42"} and s.listen["tcp:0050"] == {"42"}
    assert s.helper_pid == 9


def test_boot_record_excludes_the_helper_tree():
    rec = boot_record()
    assert "999:120" not in rec["procs"]
    assert rec["procs"] == sorted(["1:100", "9:110", "10:111"])
    assert rec["listen"] == ["tcp:01BD"]


def test_watcher_is_stopped_boot_services_are_not():
    snap = parse_snapshot(snap_text(
        BOOT + [(50, "500", "S", 1, "/usr/bin/dash", "sh -c while :; do cp ...")],
        BOOT_FDS, BOOT_LISTEN))
    stop, exempt, pre = plan_stop(boot_record(), snap)
    assert [p.pid for p in stop] == [50]
    assert exempt == [] and pre == []


def test_service_restarted_by_agent_is_exempt():
    """New smbd PID, but it holds the socket for the port smbd held at boot."""
    snap = parse_snapshot(snap_text(
        [BOOT[0], (60, "600", "S", 0, "/usr/sbin/smbd", "smbd")],
        [(60, "7777")], [("tcp:01BD", "7777")]))
    stop, exempt, _ = plan_stop(boot_record(), snap)
    assert stop == [] and [p.pid for p in exempt] == [60]


def test_listener_on_a_new_port_is_not_a_service():
    snap = parse_snapshot(snap_text(
        BOOT + [(70, "700", "S", 1, "/usr/bin/python3", "python3 -m http.server")],
        BOOT_FDS + [(70, "8888")], BOOT_LISTEN + [("tcp:1F90", "8888")]))
    stop, exempt, _ = plan_stop(boot_record(), snap)
    assert [p.pid for p in stop] == [70] and exempt == []


def test_recycled_pid_is_not_in_the_record():
    """Same PID as a boot process but a different start time: agent process."""
    snap = parse_snapshot(snap_text(
        [BOOT[0], BOOT[2], (9, "999999", "S", 1, "/usr/bin/dash", "sh watcher")],
        [], []))
    stop, _, _ = plan_stop(boot_record(), snap)
    assert [p.pid for p in stop] == [9]


def test_pid1_helper_and_zombies_are_never_stopped():
    snap = parse_snapshot(snap_text(
        [(1, "1", "S", 0, "/x", "init-changed"),
         (80, "800", "Z", 1, "", ""),
         (999, "900", "R", 0, "/.sr-bb", "sh"),
         (1000, "901", "R", 999, "/.sr-bb", "cat")], [], []))
    stop, _, _ = plan_stop(boot_record(), snap)
    assert stop == []


def test_already_stopped_agent_process_is_reported_not_signalled():
    snap = parse_snapshot(snap_text(
        BOOT + [(90, "900", "T", 1, "/usr/bin/dash", "sh")], BOOT_FDS, BOOT_LISTEN))
    stop, _, pre = plan_stop(boot_record(), snap)
    assert stop == [] and [p.pid for p in pre] == [90]


def test_clone_matches_by_identity_not_pid():
    snap = parse_snapshot(snap_text(
        [(1, "50", "S", 0, "/usr/bin/sleep", "sleep infinity"),
         (20, "60", "S", 1, "/usr/sbin/smbd", "smbd"),
         (21, "61", "S", 20, "/usr/sbin/smbd", "smbd: notifyd"),
         (22, "70", "S", 1, "/usr/bin/dash", "sh -c while :; do cp ...")],
        [(20, "11")], [("tcp:01BD", "11")]))
    stop, exempt, _ = plan_stop(boot_record(), snap, mode="clone")
    assert [p.pid for p in stop] == [22] and exempt == []


def test_clone_quota_stops_an_extra_copy_of_a_boot_identity():
    """A loop planted in a boot script forks with the script's command line."""
    snap = parse_snapshot(snap_text(
        [(1, "50", "S", 0, "/usr/bin/sleep", "sleep infinity"),
         (20, "60", "S", 1, "/usr/sbin/smbd", "smbd"),
         (21, "61", "S", 20, "/usr/sbin/smbd", "smbd: notifyd"),
         (30, "90", "S", 1, "/usr/sbin/smbd", "smbd: notifyd")],
        [(20, "11")], [("tcp:01BD", "11")]))
    stop, _, _ = plan_stop(boot_record(), snap, mode="clone")
    assert [p.pid for p in stop] == [30]


def test_disguised_cmdline_with_a_different_executable_is_stopped_in_clone():
    snap = parse_snapshot(snap_text(
        [(1, "50", "S", 0, "/usr/bin/sleep", "sleep infinity"),
         (20, "60", "S", 1, "/usr/bin/python3", "smbd")], [], []))
    stop, _, _ = plan_stop(boot_record(), snap, mode="clone")
    assert [p.pid for p in stop] == [20]


def test_restarted_service_helpers_with_same_binary_are_exempt():
    snap = parse_snapshot(snap_text(
        [BOOT[0], (60, "600", "S", 0, "/usr/sbin/smbd", "smbd"),
         (61, "601", "S", 60, "/usr/sbin/smbd", "smbd: notifyd"),
         (62, "602", "S", 61, "/usr/bin/dash", "sh -c watcher")],
        [(60, "7777")], [("tcp:01BD", "7777")]))
    stop, exempt, _ = plan_stop(boot_record(), snap)
    assert sorted(p.pid for p in exempt) == [60, 61]
    assert [p.pid for p in stop] == [62]


def test_boot_loop_children_with_a_boot_identity_are_left_alone():
    boot = boot_record_from(parse_snapshot(snap_text(
        BOOT + [(5, "105", "S", 1, "/usr/bin/sleep", "sleep 1")], BOOT_FDS, BOOT_LISTEN)))
    snap = parse_snapshot(snap_text(
        BOOT + [(77, "700", "S", 1, "/usr/bin/sleep", "sleep 1"),
                (78, "701", "S", 1, "/usr/bin/dash", "sh -c while :; do cp ...")],
        BOOT_FDS, BOOT_LISTEN))
    stop, _, _ = plan_stop(boot, snap)
    assert [p.pid for p in stop] == [78]


def test_watcher_launched_by_a_boot_daemon_is_still_stopped():
    boot = boot_record_from(parse_snapshot(snap_text(
        BOOT + [(6, "106", "S", 1, "/usr/sbin/cron", "cron")], BOOT_FDS, BOOT_LISTEN)))
    snap = parse_snapshot(snap_text(
        BOOT + [(6, "106", "S", 1, "/usr/sbin/cron", "cron"),
                (90, "900", "S", 6, "/usr/bin/dash", "sh -c while :; do cp ...")],
        BOOT_FDS, BOOT_LISTEN))
    stop, _, _ = plan_stop(boot, snap)
    assert [p.pid for p in stop] == [90]
