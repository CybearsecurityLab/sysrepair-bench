#!/usr/bin/env python3
"""Check that threat.md briefings disclose the vulnerability without prescribing the fix.

A Day-1 briefing is a vulnerability disclosure, in the style of CVE-Bench or
exploit-bench. It says WHAT IS WRONG. It must not say WHAT TO DO, WHAT TO RUN,
or WHAT THE VERIFIER CHECKS.

This is a lint, not a proof: it flags candidates for human review. It errs
toward false positives, because a missed leak silently weakens the Day-1
condition while a false positive costs one glance.

Exit 1 if anything is flagged.

    python scripts/check_threat_briefings.py [--quiet]
"""
from __future__ import annotations
import argparse, glob, os, re, sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Sections whose purpose is to prescribe the fix.
FIX_HEADING = re.compile(
    r'^#{1,6}\s*(remediation|expected\s+remediation|required\s+remediation|'
    r'what\s+needs\s+to\s+be\s+fixed|expected\s+remediation\s+paths|'
    r'how\s+to\s+(fix|remediate)|fix|mitigation|solution|verification|'
    r'option\s*\d|recommended\s+action)', re.I)

# Statements of what the grader does. Worse than fix disclosure: it tells the
# agent how to satisfy the scorer rather than how to secure the host.
RUBRIC = re.compile(
    r'\b(the\s+)?(verifier|grader|scorer|checker|oracle)\b[^.\n]{0,80}?'
    r'\b(check|checks|checked|look|looks|require|requires|grade|grades|graded|'
    r'plant|plants|probe|probes|confirm|confirms|accept|accepts|expect|expects)\b'
    r'|is\s+what\s+is\s+graded|counts?\s+as\s+(a\s+)?pass'
    r'|(will|does)\s+not\s+remediate\s+this\s+scenario', re.I)

# Imperative fix guidance in prose, outside any heading.
PRESCRIPTIVE = re.compile(
    r'^\s*(?:\d+\.|[-*])?\s*(?:you\s+(?:should|must)\s+|'
    r'(?:the\s+)?(?:fix|remediation|solution)\s+is\s+to\s+|'
    r'to\s+(?:fix|remediate|resolve)\s+this)', re.I)

# References to the grading machinery. A briefing that names verify.sh, or shows
# how to invoke it, hands the agent the grader rather than the vulnerability.
GRADER_PATH = re.compile(r'verify\.sh|/verify\b|docker\s+exec[^\n]*verify', re.I)

# Commands that APPLY a change. Read-only commands are fine: naming a path or
# showing how to observe the vulnerable state is disclosure.
MUTATING_CMD = re.compile(
    r'\b(apt-get\s+(install|remove|purge|upgrade)|apt\s+(install|remove|purge)|'
    r'yum\s+(install|remove|update)|dnf\s+(install|remove)|'
    r'systemctl\s+(restart|stop|disable|mask|enable)|service\s+\S+\s+(restart|stop)|'
    r'chmod\s|chown\s|chattr\s|setcap\s|usermod\s|userdel\s|(?<!/etc/)\bpasswd\s+-|'
    r'sed\s+-i|tee\s+/etc|>\s*/etc/|a2dismod|a2enmod|ufw\s+(allow|deny|enable)|'
    r'iptables\s+-[AID]|update-rc\.d|REVOKE\s|ALTER\s+USER|SET\s+PASSWORD|'
    r'rm\s+-rf?\s|mv\s+/etc|visudo)', re.I)


def check(path: str) -> list[str]:
    hits: list[str] = []
    try:
        text = open(path, errors="ignore").read()
    except OSError as e:
        return [f"unreadable: {e}"]

    lines = text.splitlines()
    in_fence = False
    fence_is_vulnerable_state = False
    prev_heading = ""
    # Sections that describe the broken state or the attack. Commands here show
    # what is wrong or how it is exploited, which is exactly what a disclosure
    # briefing is for.
    disclosure_section = False
    DISCLOSURE_HEAD = re.compile(
        r'vulnerab|affected|proof|exploit|attack|description|impact|'
        r'current\s+state|reframe|design\s+note|threat\s+details|constraint', re.I)

    for i, line in enumerate(lines, 1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            if in_fence:
                # A block under a "vulnerable ..." heading displays the bad
                # state, which is disclosure and is allowed to contain commands.
                fence_is_vulnerable_state = bool(
                    re.search(r'vulnerab|current|affected|proof|exploit|attack',
                              prev_heading, re.I))
            continue

        if line.startswith("#"):
            prev_heading = line
            disclosure_section = bool(DISCLOSURE_HEAD.search(line))
            if FIX_HEADING.match(line):
                hits.append(f"{i}: fix-prescribing heading: {line.strip()}")
            continue

        if RUBRIC.search(line):
            hits.append(f"{i}: rubric disclosure: {line.strip()[:110]}")

        if GRADER_PATH.search(line):
            hits.append(f"{i}: names the grader: {line.strip()[:110]}")

        if not in_fence and PRESCRIPTIVE.match(line):
            hits.append(f"{i}: prescriptive prose: {line.strip()[:110]}")

        if (MUTATING_CMD.search(line) and not fence_is_vulnerable_state
                and not disclosure_section):
            hits.append(f"{i}: mutating command: {line.strip()[:110]}")

    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true",
                    help="only print the summary line")
    ap.add_argument("--root", default=REPO,
                    help="tree to check (default: this repo). Use it to compare "
                         "against a backup without editing the script.")
    a = ap.parse_args()

    root = os.path.abspath(a.root)
    files = sorted(glob.glob(os.path.join(root, "*/scenario-*/threat.md")) +
                   glob.glob(os.path.join(root, "*/*/scenario-*/threat.md")))
    if not files:
        print("ERROR: no threat.md found", file=sys.stderr)
        return 2

    flagged = 0
    for f in files:
        hits = check(f)
        if not hits:
            continue
        flagged += 1
        if not a.quiet:
            print(f"\n{os.path.relpath(f, root)}")
            for h in hits:
                print(f"    {h}")

    print(f"\n{len(files)} briefings checked, {flagged} flagged")
    if flagged:
        print("A briefing must disclose the vulnerability, not the fix or the rubric.")
    return 1 if flagged else 0


if __name__ == "__main__":
    raise SystemExit(main())
