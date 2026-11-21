"""Sum the findings up in one number from 0 to 100, and a word for it."""

from __future__ import annotations

from collections.abc import Iterable

from .models import SEVERITIES, Finding

WEIGHTS = {"critical": 30, "high": 15, "medium": 6, "low": 2, "info": 0}

# The first finding of a rule costs its full weight and every further one half
# of it, up to this many times the weight. Five cameras with the same hole are
# one problem five times over, and should not sink the score on their own.
REPEAT_CAP = 3

# Lowest score of each band, best first.
BANDS = ((90, "good"), (70, "fair"), (40, "poor"), (0, "bad"))


def score(findings: Iterable[Finding]) -> int:
    """100 for nothing found, less for every finding, never below 0.

    A severity outside SEVERITIES costs nothing.
    """
    per_rule: dict[str, list[int]] = {}
    for finding in findings:
        per_rule.setdefault(finding.rule, []).append(WEIGHTS.get(finding.severity, 0))
    total = 0.0
    for weights in per_rule.values():
        weights.sort(reverse=True)
        first, rest = weights[0], weights[1:]
        total += min(first + sum(rest) / 2, REPEAT_CAP * first)
    return max(0, round(100 - total))


def band(score: int) -> str:
    """The band a score falls in: "good", "fair", "poor" or "bad"."""
    for lowest, name in BANDS:
        if score >= lowest:
            return name
    return "bad"


def counts(findings: Iterable[Finding]) -> dict[str, int]:
    """How many findings of each severity, most severe first. Every severity is there."""
    tally = dict.fromkeys(SEVERITIES, 0)
    for finding in findings:
        if finding.severity in tally:
            tally[finding.severity] += 1
    return tally
