"""Detect episodes that were never actually verified.

An episode can end without the oracle ever running: the episode hits its time or
working limit, the harness tears the container down, and verify.sh never
executes. The scorer then records a verdict anyway, and that verdict is a
FAILURE.

This matters because the bias is strictly one-directional. An unverified episode
is never recorded as a pass, so every one of them pushes a cell's accuracy down.
Measured on the corpus behind this paper, 52 of 1300 episodes (4.0%) were in this
state, and two cells moved from 90.5% and 85.7% to 100.0% once excluded.

"Not measured" is not the same as "failed", and conflating them is the same
defect class as scoring a crashed run as a wrong answer. Every table produced by
this artifact therefore reports measured-n alongside n.
"""
from __future__ import annotations
import re

# Matches the scorer's own explanation when the container was gone before the
# oracle could run. Kept as an explicit pattern list rather than a catch-all so
# a genuinely failing verify.sh is never silently reclassified as unmeasured.
UNMEASURED_PATTERNS = [
    r"verify could not run",
    r"container is not running",
    r"Error response from daemon",
    r"No such container",
    r"is not running",
]
_RE = re.compile("|".join(UNMEASURED_PATTERNS), re.IGNORECASE)

# Anchored at the START of a command line: `reboot`, `shutdown -h now`,
# `systemctl poweroff`, `init 0`, `Restart-Computer`. Not a substring search,
# so a log line or a sentence mentioning the word does not match.
_CMD_RE = re.compile(
    r"^\s*(sudo\s+)?("
    r"reboot|halt|poweroff"
    r"|shutdown(\s|$)"
    r"|systemctl\s+(reboot|poweroff|halt)"
    r"|init\s+[06](\s|$)"
    r"|Restart-Computer|Stop-Computer"
    r")", re.IGNORECASE)


def is_excludable(sample, working_limit=None, time_limit=None) -> bool:
    """True only for episodes that are a BENCHMARK defect, not a model failure.

    The regex alone is NOT a sufficient predicate, and using it alone inflates
    results. Of 55 unmeasured episodes in this corpus, only about half are
    excludable:

      at-cap        (~45%)  hit the budget, container torn down. The solver was
                            still working; scoring it a failure is the
                            protocol-consistent choice, and dropping it is the
                            biased "unresolved=drop" policy that passk.py
                            documents against -- measured at 100.0% reported
                            against an honest 21.7% on one 27B cell.
      model-bricked  (~4%)  the model itself ran Restart-Computer or shutdown.
                            It broke the host; that is a real failure.
      flaky         (~51%)  container never came up or died early, no limit hit,
                            frequently zero commands issued. The episode never
                            gave the solver a chance. THIS is the excludable set.

    So: matched the pattern AND did not hit a limit AND did not self-brick.
    """
    if not _matches_unmeasured(sample):
        return False
    if at_cap(sample, working_limit, time_limit):
        return False          # budget exhaustion is a failure, not a defect
    if _self_bricked(sample):
        return False          # the model broke its own host
    return True


def _self_bricked(sample) -> bool:
    """Did the model actually issue a command that reboots or halts its target?

    Only TOOL CALLS count, and only at the start of a command. Two false-positive
    sources were measured on real logs and both are excluded deliberately:

      tool OUTPUT      a service's own log text can contain "reboot"; that is
                       the RESULT of a command, not a command.
      assistant text   the model reasoning "maybe I should reboot" has not
                       rebooted anything.

    Matching either of those classified 2 of 4 failures in a sampled cell as
    self-bricked, when the true count was zero. The predicate is narrow on
    purpose: a missed self-brick is scored as an ordinary failure, which is the
    honest default, while a false positive removes a real failure from the
    capability count.
    """
    def _scan(text):
        for line in str(text or "").splitlines():
            if _CMD_RE.match(line.strip()):
                return True
        return False

    for m in (getattr(sample, "messages", None) or []):
        for tc in (getattr(m, "tool_calls", None) or []):
            args = getattr(tc, "arguments", None) or {}
            cmd = args.get("cmd") or args.get("command") or "" if isinstance(args, dict) else str(args)
            if _scan(cmd):
                return True
    # plan_and_solve drives the sandbox directly and emits no tool_calls,
    # so their commands are only visible as SandboxEvents.
    for e in (getattr(sample, "events", None) or []):
        if type(e).__name__ == "SandboxEvent" and _scan(getattr(e, "cmd", "")):
            return True
    return False


def _matches_unmeasured(sample) -> bool:
    """True if this episode's verdict rests on an oracle that never executed."""
    for _, sc in (getattr(sample, "scores", None) or {}).items():
        expl = getattr(sc, "explanation", None) or ""
        if _RE.search(str(expl)):
            return True
        md = getattr(sc, "metadata", None) or {}
        # A structured verdict with no checks at all is the same condition
        # reached by a different path.
        if md.get("verdict_source") == "structured" and not md.get("checks"):
            return True
    return False


def at_cap(sample, working_limit=None, time_limit=None, frac: float = 0.95) -> bool:
    """True if the episode was stopped by its budget rather than finishing.

    Prefers the harness's own `sample_limit` event, which is authoritative, and
    falls back to a time threshold only when no event is present (older logs).
    A threshold alone both misses limits that fired early and false-positives on
    an episode that merely finished close to its budget.

    An at-cap failure is not evidence about capability: the solver was still
    working when the clock stopped. Reported separately so a cell's failures
    split into 'tried and got it wrong' and 'ran out of budget'.
    """
    for e in (getattr(sample, "events", None) or []):
        if type(e).__name__ == "SampleLimitEvent":
            return True
        if getattr(e, "event", None) == "sample_limit":
            return True
    wt = getattr(sample, "working_time", None) or 0.0
    tt = getattr(sample, "total_time", None) or 0.0
    if working_limit and wt >= frac * working_limit:
        return True
    if time_limit and tt >= frac * time_limit:
        return True
    return False
