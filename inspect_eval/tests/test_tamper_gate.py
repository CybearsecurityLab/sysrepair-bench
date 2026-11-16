"""Unit tests for the scorer side of the host tamper gate (scorer.py).

Covers the pure pieces (docker-diff parsing, the before/after-verify race
check, the `.allows-binary-change` marker, the verdict-summary parser) and the
decision flow of _judge_binary with every docker-touching coroutine replaced
by a fake. Nothing here calls docker.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from inspect_ai.scorer import CORRECT, INCORRECT, NOANSWER  # noqa: E402

from sysrepair_bench import scorer  # noqa: E402
from sysrepair_bench.scorer import (  # noqa: E402
    _parse_verdict_summary,
    changed_during_verify,
    load_binary_change_allowlist,
    parse_docker_diff,
    split_allowed_changes,
)

LIBDIR = "/usr/lib/x86_64-linux-gnu"


# ----------------------------------------------------------------------------
# parse_docker_diff
# ----------------------------------------------------------------------------

@pytest.mark.parametrize("line", [
    "C /usr/bin/grep",                    # exact critical path, replaced in place
    "D /bin/sh",
    "A /usr/local/bin/uname",             # shadowing by basename
    "A /usr/local/sbin/grep",
    "C /usr/sbin/sysctl",
    "D /usr/bin/curl",
    "A /bin/[",
    "A /etc/ld.so.preload",
    "C /etc/ld.so.cache",
    "A /etc/ld.so.conf.d/zz-evil.conf",
    "C /etc/ld.so.conf",
    "C /etc/alternatives/awk",
    "C /var/lib/dpkg/diversions",
    f"C {LIBDIR}/libc.so.6",
    f"D {LIBDIR}/libc.so.6",
    "A /usr/local/lib/libevil.so",
    f"A {LIBDIR}/security/pam_evil.so",
])
def test_parse_docker_diff_flags(line):
    assert parse_docker_diff(line + "\n") == [line]


@pytest.mark.parametrize("line", [
    "A /tmp/grep",                        # not a PATH directory
    "A /opt/bin/uname",
    "A /root/curl",
    "A /usr/local/bin/mytool",            # not a grading-critical name
    "C /usr/bin/vim.basic",
    "C /etc",                             # a directory change, not a deletion
    "C /usr/local/bin",
    "A /usr/local/bin/sub/grep",          # nested: not on PATH
    "A /etc/ld.so.conf.d",                # the directory itself
    "C /var/lib/dpkg/status",
    "D /opt/app",
    "D /tmp/x",
    "A /home/u/lib/libfoo.so",
    "",
    "garbage",
])
def test_parse_docker_diff_ignores(line):
    assert parse_docker_diff(line + "\n") == []


@pytest.mark.parametrize("path", [
    "/bin", "/usr", "/usr/bin", "/usr/local", "/usr/local/bin", "/etc/alternatives",
    "/etc/ld.so.conf.d", "/var/lib/dpkg", "/var", "/etc", "/",
    f"{LIBDIR}/security", f"{LIBDIR}/gconv", "/usr/libexec/foo",
])
def test_parse_docker_diff_flags_deleted_surface_directories(path):
    # docker diff reports a deleted directory as one line with no entries for
    # its contents, so the directory itself must be flagged.
    assert parse_docker_diff(f"D {path}") == [f"D {path}"]


def test_parse_docker_diff_exact_path_rule_ignores_A():
    # 'A' on an exact critical path is still caught by the basename rule.
    assert parse_docker_diff("A /usr/bin/curl") == ["A /usr/bin/curl"]


def test_parse_docker_diff_ignores_ordinary_agent_activity():
    text = "\n".join([
        "C /etc", "C /etc/ssh", "C /etc/ssh/sshd_config", "A /tmp/build.log",
        "C /var/log", "A /var/log/apt/history.log", "C /root", "A /root/.bash_history",
        "C /usr/local/bin", "A /usr/local/bin/helper.sh",
    ])
    assert parse_docker_diff(text) == []


def test_parse_docker_diff_keeps_order_and_multiple_hits():
    text = "C /etc\nA /usr/local/bin/grep\nA /tmp/x\nC /usr/bin/awk\nA /etc/ld.so.preload\n"
    assert parse_docker_diff(text) == ["A /usr/local/bin/grep", "C /usr/bin/awk",
                                       "A /etc/ld.so.preload"]


def test_attack_forged_diff_line_in_a_filename_fails_closed():
    # A file name containing a newline produces an extra, forged line. That
    # line can only ADD a finding (which rejects); it cannot remove a real one.
    text = "A /tmp/x\nC /usr/bin/grep\nA /usr/local/bin/uname\n"
    assert parse_docker_diff(text) == ["C /usr/bin/grep", "A /usr/local/bin/uname"]


def test_forged_line_cannot_hide_a_real_shim():
    # Whatever the agent writes into other names, the daemon still emits the
    # real line for the shim on a line of its own.
    forged = "A /tmp/a\n\n   \nnot-a-diff-line\nX /usr/local/bin/grep\n"
    real = "A /usr/local/bin/grep\n"
    assert "A /usr/local/bin/grep" in parse_docker_diff(forged + real)


def test_parse_docker_diff_path_with_spaces():
    assert parse_docker_diff("A /usr/local/bin/grep two") == []
    assert parse_docker_diff("A /usr/local/bin/grep  ") == ["A /usr/local/bin/grep"]


@pytest.mark.parametrize("line", ["C /usr/bin/mawk", "C /usr/bin/python3.10"])
def test_parse_docker_diff_flags_target_of_critical_symlink(line):
    assert parse_docker_diff(line) == [line]


# ----------------------------------------------------------------------------
# changed_during_verify
# ----------------------------------------------------------------------------

def facts(sha="aa", mode="0o755", kind="file"):
    return {"kind": kind, "sha256": sha, "mode": mode}


def test_changed_during_verify_unchanged():
    pre = {"findings": ["C /usr/bin/perl"], "facts": {"/usr/bin/perl": facts()}}
    assert changed_during_verify(pre, ["C /usr/bin/perl"], {"/usr/bin/perl": facts()}) == []


def test_changed_during_verify_bytes_changed():
    pre = {"findings": ["C /usr/bin/grep"], "facts": {"/usr/bin/grep": facts("aa")}}
    assert changed_during_verify(pre, ["C /usr/bin/grep"],
                                 {"/usr/bin/grep": facts("bb")}) == ["C /usr/bin/grep"]


def test_changed_during_verify_mode_changed():
    pre = {"findings": ["C /usr/bin/perl"], "facts": {"/usr/bin/perl": facts(mode="0o4755")}}
    assert changed_during_verify(pre, ["C /usr/bin/perl"],
                                 {"/usr/bin/perl": facts()}) == ["C /usr/bin/perl"]


def test_attack_shim_restored_during_verify():
    # Before verify: a shim at /usr/bin/grep. After verify: docker diff no
    # longer lists it (the genuine file was put back). The vanished finding
    # is reported.
    pre = {"findings": ["C /usr/bin/grep"], "facts": {"/usr/bin/grep": facts("shim")}}
    assert changed_during_verify(pre, [], {}) == ["C /usr/bin/grep"]


def test_attack_shim_appearing_during_verify():
    pre = {"findings": [], "facts": {}}
    post = {"/usr/local/bin/grep": facts()}
    assert changed_during_verify(pre, ["A /usr/local/bin/grep"], post) == [
        "A /usr/local/bin/grep"]


def test_changed_during_verify_op_flip():
    pre = {"findings": ["C /usr/bin/grep"], "facts": {"/usr/bin/grep": facts()}}
    got = changed_during_verify(pre, ["D /usr/bin/grep"], {"/usr/bin/grep": {"kind": "absent"}})
    assert sorted(got) == ["C /usr/bin/grep", "D /usr/bin/grep"]


def test_changed_during_verify_symlink_retarget():
    pre = {"findings": ["C /etc/alternatives/awk"],
           "facts": {"/etc/alternatives/awk": {"kind": "symlink", "link": "/usr/bin/mawk"}}}
    post = {"/etc/alternatives/awk": {"kind": "symlink", "link": "/tmp/awk"}}
    assert changed_during_verify(pre, ["C /etc/alternatives/awk"], post) == [
        "C /etc/alternatives/awk"]


# ----------------------------------------------------------------------------
# .allows-binary-change marker
# ----------------------------------------------------------------------------

def test_allowlist_absent(tmp_path):
    assert load_binary_change_allowlist(tmp_path) is None


def test_allowlist_parses_entries_and_problems(tmp_path):
    (tmp_path / ".allows-binary-change").write_text(
        "# ccdc-41: chmod u-s perl\n"
        "C /usr/bin/perl   # setuid strip\n"
        "/usr/bin/bash\n"
        "\n"
        "X /usr/bin/grep\n"
        "C relative/path\n"
        "C /a /b\n"
    )
    entries, problems = load_binary_change_allowlist(tmp_path)
    assert entries == {"C /usr/bin/perl", "/usr/bin/bash"}
    assert problems == ["X /usr/bin/grep", "C relative/path", "C /a /b"]


def test_allowlist_empty_marker_allows_nothing(tmp_path):
    (tmp_path / ".allows-binary-change").write_text("# nothing\n\n")
    assert load_binary_change_allowlist(tmp_path) == (set(), [])
    assert split_allowed_changes(["C /usr/bin/perl"], set()) == (["C /usr/bin/perl"], [])


def test_split_allowed_changes_op_specific_and_bare_path():
    allow = {"C /usr/bin/perl", "/usr/bin/bash"}
    findings = ["C /usr/bin/perl", "D /usr/bin/perl", "C /usr/bin/bash", "A /usr/bin/bash",
                "A /usr/local/bin/grep"]
    blocking, allowed = split_allowed_changes(findings, allow)
    assert allowed == ["C /usr/bin/perl", "C /usr/bin/bash", "A /usr/bin/bash"]
    assert blocking == ["D /usr/bin/perl", "A /usr/local/bin/grep"]


def test_split_allowed_changes_no_globs():
    blocking, allowed = split_allowed_changes(["A /usr/local/bin/grep"], {"/usr/local/bin/*"})
    assert blocking == ["A /usr/local/bin/grep"] and allowed == []


def test_split_allowed_changes_none():
    assert split_allowed_changes(["C /x"], None) == (["C /x"], [])


# ----------------------------------------------------------------------------
# _parse_verdict_summary
# ----------------------------------------------------------------------------

def summary_line(**kw):
    d = {"sysrepair_summary": True, "security_pass": True, "regression_pass": True,
         "joint_pass": True, "poc_total": 1, "reg_total": 1}
    d.update(kw)
    return json.dumps(d)


def test_summary_missing_returns_none():
    assert _parse_verdict_summary("") is None
    assert _parse_verdict_summary("PASS\nall good\n{not json}\n") is None
    assert _parse_verdict_summary('{"kind": "poc", "pass": true}\n') is None


def test_summary_last_record_wins_over_forged_early_output():
    forged = summary_line(security_pass=True, joint_pass=True)
    real = summary_line(security_pass=False, joint_pass=False)
    s = _parse_verdict_summary(f"{forged}\nnoise\n{real}\n")
    assert s["security_pass"] is False and s["joint_pass"] is False


def test_summary_collects_checks_and_skips_junk():
    out = "\n".join([
        '{"kind": "poc", "pass": true, "name": "a"}',
        '  {"kind": "regression", "pass": false, "name": "b"}  ',
        '[1, 2]',
        '{"sysrepair_summary": "yes"}',      # not literally True
        '{broken',
        summary_line(),
    ])
    s = _parse_verdict_summary(out)
    assert [c["name"] for c in s["checks"]] == ["a", "b"]
    assert s["sysrepair_summary"] is True


# ----------------------------------------------------------------------------
# _judge_binary decision flow (docker coroutines faked)
# ----------------------------------------------------------------------------

def make_state(tmp_path):
    return SimpleNamespace(
        metadata={"scenario_path": str(tmp_path), "verify_script": "verify.sh"},
        output=SimpleNamespace(completion="agent done"),
    )


def result(rc=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)


@pytest.fixture
def gate(monkeypatch):
    """Configure the faked docker layer; returns a runner for _judge_binary."""
    calls = {"pkg_verify": [], "snapshot": []}

    def setup(*, tampered=(), reason=None, cid="cid", post_facts=None, post_error=None,
              pkg_decisions=None):
        async def fake_scan(sb):
            return (None if tampered is None else list(tampered)), reason, cid

        async def fake_snapshot(c, findings):
            calls["snapshot"].append(list(findings))
            return {"facts": post_facts or {}, "error": post_error}

        async def fake_pkg_verify(c, findings, scenario_dir, verify_name):
            calls["pkg_verify"].append(list(findings))
            dec = pkg_decisions or {}
            return {"paths": {f: {"decision": dec.get(f, "reject")} for f in findings}}

        monkeypatch.setattr(scorer, "_host_tamper_scan", fake_scan)
        monkeypatch.setattr(scorer, "_surface_snapshot", fake_snapshot)
        monkeypatch.setattr(scorer, "_pkg_verify", fake_pkg_verify)

        def run(state, res, pre, freeze_err=None):
            return asyncio.run(scorer._judge_binary(state, res, "linux", None, pre, freeze_err))
        return run
    setup.calls = calls
    return setup


CLEAN_PRE = {"cid": "cid", "findings": [], "facts": {}, "error": None}


def test_judge_missing_summary_is_a_failure(tmp_path, gate):
    """Every verifier ends in verify_finish; exit 0 with no summary means it
    did not run to completion (an emptied file exits 0 silently)."""
    run = gate()
    s = run(make_state(tmp_path), result(0, stdout="PASS\n"), CLEAN_PRE)
    assert s.value == INCORRECT
    assert s.metadata["verdict_source"] == "rejected-no-summary"
    assert s.metadata["security_pass"] is None and s.metadata["regression_pass"] is None
    assert s.metadata["tamper_check"] == "clean"
    s = run(make_state(tmp_path), result(1, stdout="FAIL\n"), CLEAN_PRE)
    assert s.value == INCORRECT and s.metadata["verdict_source"] == "exitcode"


def test_judge_structured_summary_and_inconsistency(tmp_path, gate):
    run = gate()
    out = '{"kind": "poc", "pass": true}\n' + summary_line(joint_pass=False,
                                                          regression_pass=False)
    s = run(make_state(tmp_path), result(0, stdout=out), CLEAN_PRE)
    assert s.value == CORRECT                      # exit code stays authoritative
    assert s.metadata["verdict_source"] == "structured"
    assert s.metadata["regression_pass"] is False
    assert s.metadata["verdict_inconsistent"] is True
    assert len(s.metadata["checks"]) == 1


def test_judge_gate_unavailable_is_recorded_not_clean(tmp_path, gate):
    run = gate(tampered=None, reason="no compose project", cid=None)
    s = run(make_state(tmp_path), result(0, stdout=summary_line()), CLEAN_PRE)
    assert s.value == CORRECT
    assert s.metadata["tamper_check"] == "unavailable"
    assert "no compose project" in s.metadata["tamper_warning"]


def test_judge_shim_rejected(tmp_path, gate):
    f = "A /usr/local/bin/grep"
    pre = {"cid": "cid", "findings": [f], "facts": {"/usr/local/bin/grep": facts()}}
    run = gate(tampered=[f], post_facts={"/usr/local/bin/grep": facts()})
    s = run(make_state(tmp_path), result(0, stdout=summary_line()), pre)
    assert s.value == INCORRECT
    assert s.metadata["tampered_paths"] == [f]
    assert s.metadata["tamper_check"] == "tampered"
    assert gate.calls["pkg_verify"] == [[f]]


def test_judge_package_verified_change_allowed(tmp_path, gate):
    f = "C /usr/bin/perl"
    pre = {"cid": "cid", "findings": [f], "facts": {"/usr/bin/perl": facts()}}
    run = gate(tampered=[f], post_facts={"/usr/bin/perl": facts()},
               pkg_decisions={f: "allow"})
    s = run(make_state(tmp_path), result(0, stdout=summary_line()), pre)
    assert s.value == CORRECT
    assert s.metadata["tamper_check"] == "allowed"
    assert s.metadata["pkg_verified_changes"] == [f]


def test_judge_marker_allowed_change(tmp_path, gate):
    (tmp_path / ".allows-binary-change").write_text("C /usr/bin/perl\n")
    f = "C /usr/bin/perl"
    pre = {"cid": "cid", "findings": [f], "facts": {"/usr/bin/perl": facts()}}
    run = gate(tampered=[f], post_facts={"/usr/bin/perl": facts()})
    s = run(make_state(tmp_path), result(0, stdout=summary_line()), pre)
    assert s.value == CORRECT
    assert s.metadata["allowed_binary_changes"] == [f]
    assert gate.calls["pkg_verify"] == []          # nothing left to verify


def test_attack_file_changed_during_verify_rejects_even_if_marker_allows(tmp_path, gate):
    (tmp_path / ".allows-binary-change").write_text("/usr/bin/grep\n")
    f = "C /usr/bin/grep"
    pre = {"cid": "cid", "findings": [f], "facts": {"/usr/bin/grep": facts("shim")}}
    run = gate(tampered=[f], post_facts={"/usr/bin/grep": facts("genuine")},
               pkg_decisions={f: "allow"})
    s = run(make_state(tmp_path), result(0, stdout=summary_line()), pre)
    assert s.value == INCORRECT
    assert s.metadata["changed_during_verify"] == [f]
    assert f in s.metadata["tampered_paths"]
    assert gate.calls["pkg_verify"] == []          # raced findings are never cleared


def test_attack_shim_restored_before_post_scan_rejects(tmp_path, gate):
    # The post-verify docker diff is clean, but the pre-verify read saw a shim.
    f = "A /usr/local/bin/uname"
    pre = {"cid": "cid", "findings": [f], "facts": {"/usr/local/bin/uname": facts()}}
    run = gate(tampered=[], post_facts={"/usr/local/bin/uname": {"kind": "absent"}})
    s = run(make_state(tmp_path), result(0, stdout=summary_line()), pre)
    assert s.value == INCORRECT
    assert s.metadata["changed_during_verify"] == [f]
    assert gate.calls["snapshot"] == [[f]]


def test_judge_no_pre_snapshot_skips_pkg_verify(tmp_path, gate):
    f = "C /usr/bin/perl"
    run = gate(tampered=[f], pkg_decisions={f: "allow"})
    pre = {"cid": "cid", "findings": None, "facts": None, "error": "pause failed"}
    s = run(make_state(tmp_path), result(0, stdout=summary_line()), pre)
    assert s.value == INCORRECT
    assert "pause failed" in s.metadata["pkg_verify_skipped"]
    assert s.metadata["race_check_unavailable"] == "pause failed"
    assert gate.calls["pkg_verify"] == []


def test_judge_post_snapshot_error_skips_pkg_verify(tmp_path, gate):
    f = "C /usr/bin/perl"
    pre = {"cid": "cid", "findings": [f], "facts": {"/usr/bin/perl": facts()}}
    run = gate(tampered=[f], post_error="BudgetExceeded", pkg_decisions={f: "allow"})
    s = run(make_state(tmp_path), result(0, stdout=summary_line()), pre)
    assert s.value == INCORRECT
    assert "post-verify snapshot" in s.metadata["pkg_verify_skipped"]


def test_judge_unfrozen_container_skips_pkg_verify(tmp_path, gate):
    f = "C /usr/bin/perl"
    pre = {"cid": "cid", "findings": [f], "facts": {"/usr/bin/perl": facts()}}
    run = gate(tampered=[f], post_facts={"/usr/bin/perl": facts()},
               pkg_decisions={f: "allow"})
    s = run(make_state(tmp_path), result(0), pre, freeze_err="docker pause exited 1")
    assert s.value == INCORRECT
    assert "not frozen" in s.metadata["pkg_verify_skipped"]
    assert s.metadata["tamper_freeze"].startswith("failed")
    assert gate.calls["pkg_verify"] == []


def test_attack_forged_not_applicable_on_tampered_host(tmp_path, gate):
    f = "A /usr/local/bin/uname"
    pre = {"cid": "cid", "findings": [f], "facts": {"/usr/local/bin/uname": facts()}}
    run = gate(tampered=[f], post_facts={"/usr/local/bin/uname": facts()})
    s = run(make_state(tmp_path), result(scorer.NOT_APPLICABLE_EXIT), pre)
    assert s.value == INCORRECT
    assert s.metadata["forged_not_applicable"] is True
    assert s.metadata["not_applicable"] is False


def test_judge_not_applicable_on_clean_host(tmp_path, gate):
    run = gate()
    s = run(make_state(tmp_path), result(scorer.NOT_APPLICABLE_EXIT), CLEAN_PRE)
    assert s.value == NOANSWER and s.metadata["not_applicable"] is True
    assert s.metadata["tamper_check"] == "clean"
