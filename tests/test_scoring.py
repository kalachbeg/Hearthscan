import pytest

from hearthscan.models import SEVERITIES, Finding
from hearthscan.scoring import WEIGHTS, band, counts, score


def finding(rule, severity, n=1):
    return Finding(rule, severity, f"192.168.1.{n}", 80)


def same(rule, severity, times):
    return [finding(rule, severity, n) for n in range(1, times + 1)]


def test_weights_cover_every_severity():
    assert tuple(WEIGHTS) == SEVERITIES
    assert WEIGHTS == {"critical": 30, "high": 15, "medium": 6, "low": 2, "info": 0}


def test_nothing_found_is_100():
    assert score([]) == 100
    assert band(score([])) == "good"


@pytest.mark.parametrize(
    "severity, expected",
    [("critical", 70), ("high", 85), ("medium", 94), ("low", 98), ("info", 100)],
)
def test_one_finding_costs_its_weight(severity, expected):
    assert score([finding("some-rule", severity)]) == expected


def test_repeats_of_a_rule_count_half():
    assert score(same("database-open", "medium", 2)) == 100 - 6 - 3
    assert score(same("database-open", "medium", 3)) == 100 - 6 - 3 - 3
    assert score(same("old-tls", "low", 2)) == 100 - 2 - 1
    # Two high findings cost 22.5, so the score rounds from 77.5.
    assert score(same("telnet-open", "high", 2)) == 78


def test_different_rules_each_count_in_full():
    findings = [finding("rdp-open", "medium"), finding("nfs-open", "medium")]
    assert score(findings) == 100 - 6 - 6


def test_a_rule_costs_three_times_its_weight_at_most():
    assert score(same("telnet-open", "high", 5)) == 100 - 45
    assert score(same("telnet-open", "high", 50)) == 100 - 45
    assert score(same("database-open", "medium", 5)) == 100 - 18
    assert score(same("database-open", "medium", 4)) == 100 - 6 - 9
    assert score(same("vnc-no-auth", "critical", 3)) == 100 - 30 - 30
    assert score(same("vnc-no-auth", "critical", 9)) == 10


def test_info_never_costs_anything():
    assert score(same("ssh-open", "info", 40)) == 100


def test_score_never_drops_below_zero():
    findings = [finding(f"rule-{n}", "critical") for n in range(4)]
    assert score(findings) == 0
    assert score(findings * 3) == 0


def test_unknown_severity_costs_nothing():
    assert score([finding("odd-rule", "catastrophic")]) == 100


def test_score_takes_any_iterable():
    assert score(finding("telnet-open", "high", n) for n in range(1, 3)) == 78


@pytest.mark.parametrize(
    "value, expected",
    [
        (100, "good"),
        (90, "good"),
        (89, "fair"),
        (70, "fair"),
        (69, "poor"),
        (40, "poor"),
        (39, "bad"),
        (0, "bad"),
    ],
)
def test_band_boundaries(value, expected):
    assert band(value) == expected


def test_counts_lists_every_severity():
    assert counts([]) == dict.fromkeys(SEVERITIES, 0)
    findings = [
        *same("vnc-no-auth", "critical", 2),
        finding("ssh-open", "info"),
        finding("odd-rule", "catastrophic"),
    ]
    tally = counts(findings)
    assert list(tally) == list(SEVERITIES)
    assert tally == {"critical": 2, "high": 0, "medium": 0, "low": 0, "info": 1}
