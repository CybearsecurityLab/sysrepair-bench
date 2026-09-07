"""pass@K for one episode's sequential submit attempts.

An episode is one (scenario, epoch) run in which the solver may submit up to K
times, receiving the oracle's verdict between attempts. The harness stops at the
first passing attempt, so a solved episode records fewer than K outcomes.

This is NOT the Chen et al. estimator. That formula draws k of n observed
attempts at random and is unbiased only when attempts are exchangeable. Here the
solver sees the verifier's failure feedback between attempts, so later attempts
are systematically better informed and exchangeability fails. We therefore read
off the process that actually happened: was the episode solved within the first
K attempts.
"""
from __future__ import annotations


def prefix_pass_at(outcomes: list[bool], k: int) -> bool:
    """True if the episode was solved within its first k submit attempts.

    An episode that stopped early because it PASSED is a pass for every k at or
    above the passing attempt; it must not be dropped at higher k. Keying off
    the first passing attempt rather than len(outcomes) is what makes that hold.
    """
    if not outcomes:
        return False
    for i, ok in enumerate(outcomes[:k]):
        if ok:
            return True
    return False


def cell_pass_at(episodes: list[list[bool]], k: int) -> tuple[int, int]:
    """(passes, n) over a cell's episodes. Unresolved episodes count as failures.

    Returns counts rather than a percentage so callers can report k/N exactly.
    A percentage alone hides the denominator, and the denominator is the thing
    that most often differs between a published cell and a recomputation.
    """
    n = len(episodes)
    return sum(1 for o in episodes if prefix_pass_at(o, k)), n
