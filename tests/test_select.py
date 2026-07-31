"""Тесты классификации ASN.

Здесь живёт единственное правило, благодаря которому механизм работает для
любого сервиса, а не только для YouTube: мы **не гадаем**, принадлежит ли
домен сервису. Мы измеряем, во сколько маршрутов обойдётся ASN.

* Узкая ASN (дешевле порога) — разворачиваем целиком из IRR. Лишние
  префиксы её владельца не страшны: их мало и они того же владельца.
* Широкая ASN (Google, AWS, Cloudflare) — берём только те блоки, в которые
  реально попали отрезолвленные адреса. Развернуть AS15169 целиком значит
  увести к себе весь трафик Google, включая тот, о котором нас не просили.

Цена ASN считается ПОСЛЕ схлопывания. Это не деталь: AS15169 — 1831
route-объект и 83 маршрута, и от того, какое из чисел сравнивать с порогом,
зависит, попадёт ли главная ASN YouTube под ограничение.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from bgpfeed.config import AsnPolicy
from bgpfeed.select import AsnVerdict, classify_asn, classify_all

POLICY = AsnPolicy(trusted_max_prefixes=2000)


def verdict(asn, seen_ips=("1.1.1.1",), prefix_count=10, policy=POLICY, **kw):
    return classify_asn(asn, seen_ips=set(seen_ips), prefix_count=prefix_count,
                        policy=policy, **kw)


# --- пороги ---

def test_narrow_asn_is_trusted():
    assert verdict(200019, prefix_count=190).tier == "trusted"


def test_wide_asn_is_fully_trusted():
    """Размер ASN не имеет права урезать полное покрытие."""
    assert verdict(16509, prefix_count=4902).tier == "trusted"


def test_google_is_trusted_at_real_cost():
    """AS15169 стоит 83 маршрута, а не 1831 — порог её не задевает."""
    assert verdict(15169, prefix_count=83).tier == "trusted"


def test_raw_count_cannot_limit_an_asn():
    """Контрольный тест на ту самую ошибку.

    У AS15169 три разных числа: 3508 route-объектов в ответе RADB, 1831
    уникальный префикс, 83 маршрута после схлопывания. Сравнивать с порогом
    надо последнее; первое увело бы главную ASN YouTube в limited.
    """
    assert verdict(15169, prefix_count=3508).tier == "trusted"
    assert verdict(15169, prefix_count=83).tier == "trusted"


def test_exactly_at_threshold_is_trusted():
    assert verdict(1, prefix_count=2000).tier == "trusted"


def test_one_over_threshold_is_still_trusted():
    assert verdict(1, prefix_count=2001).tier == "trusted"


def test_real_fixture_costs_land_on_the_right_side_of_the_threshold():
    """Привязка порога к настоящим данным, а не к выдуманным числам."""
    import gzip
    import os

    from bgpfeed.irr import parse_route_objects
    from bgpfeed.summarize import prefix_count as cost

    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    with gzip.open(os.path.join(fixtures, "radb_as15169.txt.gz"), "rt",
                   encoding="utf-8", errors="replace") as handle:
        google = parse_route_objects(handle.read())
    with gzip.open(os.path.join(fixtures, "radb_as16509.txt.gz"), "rt",
                   encoding="utf-8", errors="replace") as handle:
        aws = parse_route_objects(handle.read())

    assert verdict(15169, prefix_count=cost(google)).tier == "trusted"
    assert verdict(16509, prefix_count=cost(aws)).tier == "trusted"


# --- явные списки ---

def test_explicitly_trusted_asn_survives_size():
    """Оператор перечислил ASN руками — размер больше не аргумент."""
    policy = AsnPolicy(trusted_max_prefixes=2000, trusted_asns=(16509,))
    assert verdict(16509, prefix_count=4902, policy=policy).tier == "trusted"


def test_excluded_asn_is_rejected():
    policy = AsnPolicy(exclude_asns=(15169,))
    assert verdict(15169, prefix_count=83, policy=policy).tier == "rejected"


def test_exclusion_beats_explicit_trust():
    """Явный запрет сильнее явного доверия: запрет — это всегда осознанный шаг."""
    policy = AsnPolicy(trusted_asns=(15169,), exclude_asns=(15169,))
    assert verdict(15169, prefix_count=83, policy=policy).tier == "rejected"


# --- порог по числу адресов ---

def test_asn_with_too_few_ips_rejected():
    """Один адрес на огромную ASN — скорее всего, случайный CNAME на сторону."""
    policy = AsnPolicy(min_ips=3)
    assert verdict(13335, seen_ips=("1.1.1.1",), policy=policy).tier == "rejected"


def test_asn_meeting_min_ips_accepted():
    policy = AsnPolicy(min_ips=3)
    assert verdict(15169, seen_ips=("1.1.1.1", "2.2.2.2", "3.3.3.3"),
                   prefix_count=83, policy=policy).tier == "trusted"


def test_min_ips_does_not_apply_to_explicit_asns():
    policy = AsnPolicy(min_ips=5, trusted_asns=(36561,))
    assert verdict(36561, seen_ips=("1.1.1.1",), policy=policy).tier == "trusted"


# --- обоснование ---

def test_verdict_explains_itself():
    """`show asns` печатает эту причину — она обязана быть человекочитаемой."""
    result = verdict(16509, prefix_count=4902)
    assert "4902" in result.reason
    assert result.reason.strip()


def test_verdict_keeps_seen_ips():
    result = verdict(15169, seen_ips=("1.1.1.1", "2.2.2.2"), prefix_count=83)
    assert result.seen_ips == frozenset({"1.1.1.1", "2.2.2.2"})


def test_verdict_is_frozen():
    with pytest.raises(Exception):
        verdict(15169).tier = "rejected"


def test_verdict_records_prefix_count():
    assert verdict(15169, prefix_count=83).prefix_count == 83


# --- пакетная классификация ---

def test_classify_all_returns_verdict_per_asn():
    observed = {15169: {"1.1.1.1", "2.2.2.2"}, 16509: {"3.3.3.3"}}
    costs = {15169: 83, 16509: 4902}
    result = classify_all(observed, costs, POLICY)
    assert {v.asn for v in result} == {15169, 16509}


def test_classify_all_is_deterministic():
    observed = {15169: {"1.1.1.1"}, 16509: {"3.3.3.3"}, 200019: {"4.4.4.4"}}
    costs = {15169: 83, 16509: 4902, 200019: 190}
    first = classify_all(observed, costs, POLICY)
    second = classify_all(observed, costs, POLICY)
    assert [v.asn for v in first] == [v.asn for v in second]


def test_classify_all_sorted_by_asn():
    observed = {16509: {"3.3.3.3"}, 15169: {"1.1.1.1"}}
    costs = {15169: 83, 16509: 4902}
    result = classify_all(observed, costs, POLICY)
    assert [v.asn for v in result] == [15169, 16509]


def test_missing_cost_does_not_change_the_full_coverage_policy():
    """Сборщик сам применит covering fallback, если IRR недоступен."""
    result = classify_all({15169: {"1.1.1.1"}}, {}, POLICY)
    assert result[0].tier == "trusted"


def test_classify_all_empty():
    assert classify_all({}, {}, POLICY) == []


# --- подтверждение geoip ---
#
# Подтверждение — второй, независимый от размера признак доверия: адрес ASN
# лежит в geoip-категории сервиса. Оно расширяет порог, но никого не
# выбрасывает: «ложноположительные маршруты лучше их отсутствия».

def test_corroborated_asn_gets_a_wider_threshold():
    """Подтверждённая ASN разворачивается там, где обычная была бы срезана."""
    policy = AsnPolicy(trusted_max_prefixes=100, corroboration="soft")
    verdict = classify_asn(15169, {"1.1.1.1"}, 150, policy, corroborated=True)
    assert verdict.tier == "trusted"


def test_uncorroborated_asn_is_not_limited_by_threshold():
    policy = AsnPolicy(trusted_max_prefixes=100, corroboration="soft")
    verdict = classify_asn(64500, {"1.1.1.1"}, 150, policy, corroborated=False)
    assert verdict.tier == "trusted"


def test_corroborated_asn_is_not_limited_by_threshold():
    policy = AsnPolicy(trusted_max_prefixes=100, corroboration="soft")
    verdict = classify_asn(15169, {"1.1.1.1"}, 300, policy, corroborated=True)
    assert verdict.tier == "trusted"


def test_corroboration_is_visible_in_the_reason():
    """`show asns` обязан объяснить, почему порог оказался другим."""
    policy = AsnPolicy(trusted_max_prefixes=100, corroboration="soft")
    verdict = classify_asn(15169, {"1.1.1.1"}, 150, policy, corroborated=True)
    assert "corroborat" in verdict.reason.lower()


def test_corroboration_off_still_keeps_full_coverage():
    policy = AsnPolicy(trusted_max_prefixes=100, corroboration="off")
    verdict = classify_asn(15169, {"1.1.1.1"}, 150, policy, corroborated=True)
    assert verdict.tier == "trusted"


def test_strict_corroboration_cannot_reduce_coverage():
    policy = AsnPolicy(trusted_max_prefixes=2000, corroboration="strict")
    verdict = classify_asn(64500, {"1.1.1.1"}, 10, policy, corroborated=False)
    assert verdict.tier == "trusted"


def test_strict_still_trusts_corroborated_asns():
    policy = AsnPolicy(trusted_max_prefixes=2000, corroboration="strict")
    verdict = classify_asn(15169, {"1.1.1.1"}, 10, policy, corroborated=True)
    assert verdict.tier == "trusted"


def test_strict_does_not_reject_anyone():
    """Даже в строгом режиме ASN понижается, а не выбрасывается."""
    policy = AsnPolicy(trusted_max_prefixes=2000, corroboration="strict")
    verdict = classify_asn(64500, {"1.1.1.1"}, 10, policy, corroborated=False)
    assert verdict.tier != "rejected"


def test_manual_asn_stays_trusted_without_corroboration():
    """Оператор указал ASN руками — списку это решение не отменять."""
    policy = AsnPolicy(trusted_max_prefixes=100, corroboration="strict",
                       trusted_asns=(36561,))
    verdict = classify_asn(36561, {"1.1.1.1"}, 99999, policy, corroborated=False)
    assert verdict.tier == "trusted"


def test_excluded_asn_stays_rejected_even_if_corroborated():
    """Подтверждение — не индульгенция: явный запрет сильнее."""
    policy = AsnPolicy(exclude_asns=(64500,), corroboration="soft")
    verdict = classify_asn(64500, {"1.1.1.1"}, 10, policy, corroborated=True)
    assert verdict.tier == "rejected"


def test_classify_all_accepts_the_corroborated_set():
    observed = {15169: {"1.1.1.1"}, 64500: {"2.2.2.2"}}
    costs = {15169: 150, 64500: 150}
    policy = AsnPolicy(trusted_max_prefixes=100, corroboration="soft")
    result = classify_all(observed, costs, policy, corroborated_asns={15169})
    tiers = {v.asn: v.tier for v in result}
    assert tiers == {15169: "trusted", 64500: "trusted"}


def test_classify_all_without_corroboration_unchanged():
    """Старые вызовы без списка подтверждений работают как раньше."""
    observed = {15169: {"1.1.1.1"}}
    result = classify_all(observed, {15169: 83}, POLICY)
    assert result[0].tier == "trusted"
