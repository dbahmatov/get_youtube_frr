"""Тесты агрегации префиксов.

Главный инвариант: агрегация **точная**. Результат покрывает ровно то же
множество адресов, что и вход — ни адресом больше. Это прямое требование
пользователя: «суммировать только то, что суммируется верно».

Второй инвариант, ради которого здесь лежат реальные снимки RADB: цена
ASN в маршрутах считается ПОСЛЕ схлопывания. AS15169 — 1831 route-объект,
но всего 83 маршрута на роутере, и именно это число видно в отчёте.
"""

import gzip
import ipaddress
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from bgpfeed.summarize import summarize

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

ROUTE_RE = re.compile(r"^route6?:\s+(\S+)", re.MULTILINE)


def load_fixture(name: str) -> list:
    path = os.path.join(FIXTURES, name)
    opener = gzip.open if name.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    nets = {ipaddress.ip_network(m, strict=False) for m in ROUTE_RE.findall(text)}
    return sorted(nets)


def net(cidr: str):
    return ipaddress.ip_network(cidr)


# --- базовые свойства ---

def test_empty_input():
    assert summarize([]) == []


def test_adjacent_networks_merge():
    assert summarize([net("10.0.0.0/25"), net("10.0.0.128/25")]) == [net("10.0.0.0/24")]


def test_contained_network_absorbed():
    assert summarize([net("10.0.0.0/24"), net("10.0.0.0/28")]) == [net("10.0.0.0/24")]


def test_duplicates_collapse():
    assert summarize([net("10.0.0.0/24"), net("10.0.0.0/24")]) == [net("10.0.0.0/24")]


def test_non_adjacent_networks_stay_separate():
    """Дырка между блоками не заклеивается: это был бы чужой адрес в анонсе."""
    result = summarize([net("10.0.0.0/24"), net("10.0.2.0/24")])
    assert result == [net("10.0.0.0/24"), net("10.0.2.0/24")]


def test_almost_full_supernet_not_rounded_up():
    """Три /24 из четырёх не превращаются в /22. Никакой «почти полный» блок."""
    parts = [net("10.0.0.0/24"), net("10.0.1.0/24"), net("10.0.2.0/24")]
    result = summarize(parts)
    assert net("10.0.0.0/22") not in result
    assert result == [net("10.0.0.0/23"), net("10.0.2.0/24")]


def test_result_is_sorted():
    result = summarize([net("10.0.2.0/24"), net("10.0.0.0/24"), net("10.0.1.0/24")])
    assert result == sorted(result)


def test_ipv6_collapses():
    assert summarize([net("2001:db8::/33"), net("2001:db8:8000::/33")]) == [net("2001:db8::/32")]


def test_mixed_families_kept_apart():
    result = summarize([net("10.0.0.0/24"), net("2001:db8::/32")])
    assert net("10.0.0.0/24") in result
    assert net("2001:db8::/32") in result


def test_input_iterable_not_required_to_be_list():
    assert summarize(iter([net("10.0.0.0/25"), net("10.0.0.128/25")])) == [net("10.0.0.0/24")]


# --- инвариант точности ---

def merged_intervals(networks) -> dict:
    """Покрытие как отсортированные непересекающиеся интервалы по семействам.

    Через интервалы, а не через множество адресов: /12 у Google — это миллион
    адресов, материализовать их незачем.
    """
    by_family: dict = {}
    for network in networks:
        by_family.setdefault(network.version, []).append(
            (int(network.network_address), int(network.broadcast_address))
        )

    result = {}
    for version, spans in by_family.items():
        merged = []
        for start, end in sorted(spans):
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        result[version] = merged
    return result


@pytest.mark.parametrize(
    "fixture", ["radb_as36561.txt", "radb_as15169.txt.gz", "radb_as16509.txt.gz"]
)
def test_coverage_is_exact(fixture):
    """Агрегация не теряет и не выдумывает ни одного адреса."""
    source = load_fixture(fixture)
    assert merged_intervals(summarize(source)) == merged_intervals(source)


def test_summarize_is_idempotent():
    source = load_fixture("radb_as15169.txt.gz")
    once = summarize(source)
    assert summarize(once) == once


# --- контрольные значения на реальных снимках RADB ---

def test_as36561_collapses_to_single_prefix():
    """AS36561 в конфиге подписана «Main YouTube AS», а даёт ровно один маршрут."""
    assert len(summarize(load_fixture("radb_as36561.txt"))) == 1


def test_as15169_cost_after_collapse_is_small():
    """1831 route-объект → 83 маршрута: это настоящая цена ASN."""
    source = load_fixture("radb_as15169.txt.gz")
    assert len(source) == 1831
    assert len(summarize(source)) == 83


def test_as16509_cost_after_collapse_is_reported():
    """AWS схлопывается с 25868 до 4902; число видно в отчёте."""
    source = load_fixture("radb_as16509.txt.gz")
    assert len(source) == 25868
    assert len(summarize(source)) == 4902
