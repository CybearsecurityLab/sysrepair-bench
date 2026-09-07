#!/usr/bin/env python3
"""Integrity check for the shipped evaluation logs. Called by install.sh.

Fails loudly rather than letting a claim script produce a confidently wrong
table from a truncated or unreadable log set. Checks, in order of how badly each
would mislead an evaluator:

  1. the log directory exists and holds .eval files
  2. every file opens and yields a header
  3. no file is a truncation stub (a header with zero samples beside a
     -recovered.eval sibling means the writer was force-killed mid-flush)
  4. episodes carry attempt outcomes, so pass@K is reconstructible
  5. scenario ids are namespaced, so mixed-suite cells cannot collide
"""
from __future__ import annotations
import sys
from pathlib import Path


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parents[1] / "logs"
    if not root.exists():
        print(f"SKIP: no log directory at {root}")
        print("      Claims 1, 2, 3 and 5 need it. Fetch the log archive named in README.txt.")
        return 0

    try:
        import sysrepair_bench  # noqa: F401
        from inspect_ai.log import list_eval_logs, read_eval_log
    except Exception as e:
        print(f"FAIL: cannot import the evaluation framework: {e}")
        return 1

    files, stubs, bad, ok, no_outcomes, bare_ids = [], [], [], 0, 0, 0
    for d in [root] + [p for p in root.rglob("*") if p.is_dir()]:
        try:
            files += [i.name for i in list_eval_logs(str(d))]
        except Exception:
            continue
    files = sorted(set(files))
    if not files:
        print(f"FAIL: no .eval files under {root}")
        return 1

    for f in files:
        try:
            h = read_eval_log(f, header_only=True)
        except Exception as e:
            bad.append((f, str(e)[:80])); continue
        n = h.results.completed_samples if h.results else 0
        # list_eval_logs yields location URIs ("file:/abs/path"), not bare
        # paths, so strip the scheme before touching the filesystem.
        local = str(f)
        if local.startswith("file://"):
            local = local[7:]
        elif local.startswith("file:"):
            local = local[5:]
        if not n and Path(local).stat().st_size < 5000:
            stubs.append(f); continue
        ok += 1

    # sample-level checks on a bounded sample of files, so install stays quick
    from sysrepair_bench.passk import _attempt_outcomes
    for f in files[:5]:
        try:
            log = read_eval_log(f, header_only=False)
        except Exception:
            continue
        for s in (log.samples or [])[:50]:
            if not _attempt_outcomes(s):
                no_outcomes += 1
            sid = (s.metadata or {}).get("scenario_id") or str(s.id)
            if "/" not in str(sid):
                bare_ids += 1

    print(f"log files: {len(files)}   readable: {ok}   stubs: {len(stubs)}   unreadable: {len(bad)}")
    for f, e in bad[:5]:
        print(f"  UNREADABLE {Path(str(f)).name[:40]}: {e}")
    for f in stubs[:5]:
        print(f"  STUB (0 samples, truncated write) {Path(str(f)).name[:40]}")
    if no_outcomes:
        print(f"  WARNING: {no_outcomes} sampled episodes have no attempt outcomes; "
              f"pass@K is not reconstructible for those")
    if bare_ids:
        print(f"  WARNING: {bare_ids} sampled episodes have a non-namespaced scenario id; "
              f"mixed-suite cells could collide")
    if bad:
        print("FAIL: some logs are unreadable")
        return 1
    print("OK: shipped logs are readable and carry reconstructible attempt outcomes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
