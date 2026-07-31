"""Тесты geoip: разбор CIDR-списков и подтверждение ASN.

Фикстуры — живые списки Loyalsoldier/geoip (ref d57a38b3…): v4-часть
категории `google` (2869 CIDR) и `cloudflare` целиком (695).

Ради чего всё это, видно из одного факта: **все восемь GGC-префиксов, ради
которых в боевой конфиг руками добавляли AS396982 и AS272082, лежат в
`geoip:google`** — 136.22.2.0/23, 207.175.0.0/16, 173.255.112.0/20 и
остальные. Резолвом с vds-kg их не достать, а списком — достать.

Подтверждение проверяется отдельно: geoip не фильтр, а второй независимый
признак доверия, и он не должен никого выбрасывать.
"""

import ipaddress
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from bgpfeed.feeds import geoip

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

# Из network/nodes/vds-kg.yaml: GGC-edge, найденные через goog.json.
GGC_PREFIXES = [
    "136.22.2.0/23", "136.22.4.0/23", "136.22.8.0/22", "136.23.64.0/18",
    "207.175.0.0/16", "199.192.112.0/22", "208.81.188.0/22", "173.255.112.0/20",
]

# Адреса, реально отрезолвленные с vds-kg 30.07.
RESOLVED_ON_VDS_KG = [
    "64.233.163.100", "173.194.188.38", "142.251.150.4",
    "172.253.130.100", "74.125.71.100", "108.177.14.100",
]


def fixture(name: str) -> str:
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as handle:
        return handle.read()


def net(cidr):
    return ipaddress.ip_network(cidr)


def loader_from(mapping):
    def load(category):
        if category not in mapping:
            raise KeyError(category)
        return mapping[category]

    return load


# --- разбор ---

def test_parses_plain_cidr_list():
    assert geoip.parse("1.1.1.0/24\n8.8.8.0/24\n") == [net("1.1.1.0/24"), net("8.8.8.0/24")]


def test_parses_ipv6():
    assert geoip.parse("2001:4860::/32\n") == [net("2001:4860::/32")]


def test_bare_address_becomes_host_route():
    """Строка без маски — это /32, а не повод падать."""
    assert geoip.parse("8.8.8.8\n") == [net("8.8.8.8/32")]


def test_comments_and_blanks_ignored():
    assert geoip.parse("# заголовок\n\n1.1.1.0/24\n") == [net("1.1.1.0/24")]


def test_inline_comment_stripped():
    assert geoip.parse("1.1.1.0/24 # cloudflare\n") == [net("1.1.1.0/24")]


def test_malformed_line_is_skipped_not_fatal():
    """Обрубок вроде `136.50.167.0/` не должен ронять разбор всего списка."""
    result = geoip.parse("1.1.1.0/24\n136.50.167.0/\n8.8.8.0/24\n")
    assert result == [net("1.1.1.0/24"), net("8.8.8.0/24")]


def test_host_bits_set_are_tolerated():
    """`1.2.3.4/24` — типичная неточность в списках; берём сеть."""
    assert geoip.parse("1.2.3.4/24\n") == [net("1.2.3.0/24")]


def test_duplicates_preserved_for_the_caller_to_collapse():
    """Схлопывание — не дело парсера: он отдаёт то, что написано в файле."""
    assert len(geoip.parse("1.1.1.0/24\n1.1.1.0/24\n")) == 2


# --- загрузка категорий ---

def test_load_single_category():
    result = geoip.load_categories(["google"], loader_from({"google": "8.8.8.0/24\n"}))
    assert result.prefixes == [net("8.8.8.0/24")]


def test_load_merges_categories():
    result = geoip.load_categories(
        ["a", "b"], loader_from({"a": "1.1.1.0/24\n", "b": "8.8.8.0/24\n"})
    )
    assert set(result.prefixes) == {net("1.1.1.0/24"), net("8.8.8.0/24")}


def test_per_category_breakdown_is_kept():
    """`feeds show` печатает это, и лестница бюджета судит категории по отдельности."""
    result = geoip.load_categories(
        ["a", "b"], loader_from({"a": "1.1.1.0/24\n", "b": "8.8.8.0/24\n8.8.4.0/24\n"})
    )
    assert len(result.by_category["b"]) == 2


def test_missing_category_is_survivable():
    result = geoip.load_categories(["gone", "ok"], loader_from({"ok": "1.1.1.0/24\n"}))
    assert result.prefixes == [net("1.1.1.0/24")]
    assert result.missing == {"gone"}


def test_malformed_lines_are_counted():
    result = geoip.load_categories(["a"], loader_from({"a": "мусор\n1.1.1.0/24\n"}))
    assert result.skipped == 1


# --- подтверждение ASN ---

def test_asn_with_an_ip_in_the_feed_is_corroborated():
    observed = {15169: {"8.8.8.8"}}
    assert geoip.corroborated_asns(observed, [net("8.8.8.0/24")]) == {15169}


def test_asn_without_any_ip_in_the_feed_is_not():
    observed = {64500: {"203.0.113.9"}}
    assert geoip.corroborated_asns(observed, [net("8.8.8.0/24")]) == set()


def test_one_matching_ip_is_enough():
    """Порог — одно попадание: пропустить своих дороже, чем впустить чужих."""
    observed = {15169: {"203.0.113.9", "8.8.8.8", "192.0.2.1"}}
    assert geoip.corroborated_asns(observed, [net("8.8.8.0/24")]) == {15169}


def test_corroboration_handles_mixed_families():
    """v4 и v6 в одном списке — привычное место, где падает сортировка."""
    observed = {15169: {"2001:4860:4860::8888"}}
    prefixes = [net("8.8.8.0/24"), net("2001:4860::/32")]
    assert geoip.corroborated_asns(observed, prefixes) == {15169}


def test_corroboration_ignores_unparsable_ips():
    assert geoip.corroborated_asns({1: {"не-адрес"}}, [net("8.8.8.0/24")]) == set()


def test_empty_feed_corroborates_nobody():
    assert geoip.corroborated_asns({15169: {"8.8.8.8"}}, []) == set()


def test_corroboration_does_not_reject_anyone():
    """Подтверждение — ранжирование доверия, а не фильтр: список ASN не меняется."""
    observed = {15169: {"8.8.8.8"}, 64500: {"203.0.113.9"}}
    corroborated = geoip.corroborated_asns(observed, [net("8.8.8.0/24")])
    assert set(observed) - corroborated == {64500}


# --- реальные списки ---

def test_real_google_feed_parses():
    prefixes = geoip.parse(fixture("geoip_google_v4.txt"))
    assert len(prefixes) == 2869


def test_real_google_feed_contains_every_ggc_prefix():
    """Ровно те префиксы, ради которых AS396982 добавляли в конфиг руками."""
    prefixes = set(geoip.parse(fixture("geoip_google_v4.txt")))
    assert {net(p) for p in GGC_PREFIXES} <= prefixes


def test_real_feed_covers_addresses_resolved_on_vds_kg():
    """Резолв и список сходятся: подтверждение AS15169 сработает на живых данных."""
    prefixes = geoip.parse(fixture("geoip_google_v4.txt"))
    observed = {15169: set(RESOLVED_ON_VDS_KG)}
    assert geoip.corroborated_asns(observed, prefixes) == {15169}


def test_real_cloudflare_feed_does_not_corroborate_google_addresses():
    """Чужая категория не подтверждает — иначе признак ничего не стоил бы."""
    prefixes = geoip.parse(fixture("geoip_cloudflare.txt"))
    observed = {15169: set(RESOLVED_ON_VDS_KG)}
    assert geoip.corroborated_asns(observed, prefixes) == set()


def test_real_google_feed_size_is_reported_against_budget():
    """7735 CIDR при бюджете 20000 — заметная доля, о ней должно быть известно."""
    result = geoip.load_categories(
        ["google"], lambda c: fixture("geoip_google_v4.txt"), max_total_prefixes=1000
    )
    assert result.oversized == {"google"}


def test_category_within_budget_is_not_flagged():
    result = geoip.load_categories(
        ["cloudflare"], lambda c: fixture("geoip_cloudflare.txt"),
        max_total_prefixes=20000,
    )
    assert result.oversized == set()
