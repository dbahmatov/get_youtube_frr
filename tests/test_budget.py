"""Бюджет наблюдается, но никогда не урезает полное покрытие."""

from bgpfeed.budget import FeedVerdict, fit_all, fit_to_budget, total_cost_all
from bgpfeed.config import Budget
from bgpfeed.select import AsnVerdict


def trusted(asn, prefix_count, ips=1):
    return AsnVerdict(
        asn=asn,
        tier="trusted",
        reason="test",
        seen_ips=frozenset(f"10.0.0.{i}" for i in range(ips)),
        prefix_count=prefix_count,
    )


def announced(category, prefix_count, ips=1):
    return FeedVerdict(
        category=category,
        mode="announce",
        prefix_count=prefix_count,
        corroborated_ips=ips,
    )


def test_within_budget_changes_nothing():
    verdicts = [trusted(15169, 104), trusted(396982, 1115)]
    assert fit_to_budget(verdicts, Budget(max_total_prefixes=20000), ()) == verdicts


def test_asn_over_budget_remains_fully_trusted():
    verdicts = [trusted(16509, 4902)]
    result = fit_to_budget(verdicts, Budget(max_total_prefixes=10), ())
    assert result[0].tier == "trusted"
    assert result[0].prefix_count == 4902


def test_on_overflow_fail_cannot_reduce_or_reject_full_coverage():
    verdicts = [trusted(16509, 4902)]
    result = fit_to_budget(
        verdicts, Budget(max_total_prefixes=10, on_overflow="fail"), (),
    )
    assert result == verdicts


def test_geoip_over_budget_remains_announced():
    feed = announced("google", 7735)
    _, feeds = fit_all([], [feed], Budget(max_total_prefixes=10), ())
    assert feeds == [feed]


def test_combined_overflow_keeps_every_full_source():
    verdicts = [trusted(16509, 4902), trusted(8075, 1124)]
    feeds = [announced("google", 7735), announced("facebook", 120)]
    fitted_asns, fitted_feeds = fit_all(
        verdicts, feeds, Budget(max_total_prefixes=100), (),
    )
    assert fitted_asns == verdicts
    assert fitted_feeds == feeds


def test_explicit_corroborate_mode_is_preserved():
    feed = FeedVerdict("google", "corroborate", 7735, 1)
    _, feeds = fit_all([], [feed], Budget(max_total_prefixes=1), ())
    assert feeds == [feed]


def test_empty_input():
    assert fit_all([], [], Budget(), ()) == ([], [])


def test_total_cost_remains_observable_above_budget():
    verdicts = [trusted(16509, 4902)]
    feeds = [announced("google", 7735)]
    assert total_cost_all(verdicts, feeds) == 12637
