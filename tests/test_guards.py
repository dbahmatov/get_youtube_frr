"""Тесты защитных проверок перед анонсом.

Guards — последний рубеж между «резолв принёс мусор» и «роутер уехал».
Их задача не улучшить покрытие, а не дать анонсировать заведомо опасное:
default-route, приватные сети, петли на сам роутер.
"""

import ipaddress
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from bgpfeed.config import Guards
from bgpfeed.errors import BgpfeedError
from bgpfeed.guards import apply_guards, is_bogon


def nets(*cidrs):
    return [ipaddress.ip_network(c) for c in cidrs]


DEFAULT = Guards()


# --- bogon-фильтр ---

@pytest.mark.parametrize("cidr", [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "192.0.2.0/24",
    "::1/128",
    "fe80::/10",
    "fc00::/7",
])
def test_bogons_detected(cidr):
    assert is_bogon(ipaddress.ip_network(cidr))


@pytest.mark.parametrize("cidr", [
    "8.8.8.0/24",
    "142.250.0.0/15",
    "216.58.192.0/19",
    "2001:4860::/32",
])
def test_public_prefixes_are_not_bogons(cidr):
    assert not is_bogon(ipaddress.ip_network(cidr))


def test_subnet_of_bogon_is_bogon():
    """Проверка по вхождению, а не по точному совпадению списка."""
    assert is_bogon(ipaddress.ip_network("10.1.2.0/24"))


def test_bogons_dropped():
    kept = apply_guards(nets("8.8.8.0/24", "10.0.0.0/8"), DEFAULT)
    assert kept == nets("8.8.8.0/24")


def test_bogons_kept_when_disabled():
    policy = Guards(drop_bogons=False, min_prefix_len=8)
    kept = apply_guards(nets("8.8.8.0/24", "10.0.0.0/8"), policy)
    assert len(kept) == 2


# --- слишком широкие префиксы ---

def test_default_route_dropped():
    """0.0.0.0/0 в анонсе — это увод всего трафика. Никогда."""
    assert apply_guards(nets("0.0.0.0/0", "8.8.8.0/24"), DEFAULT) == nets("8.8.8.0/24")


def test_prefix_wider_than_min_len_dropped():
    policy = Guards(min_prefix_len=16)
    assert apply_guards(nets("8.0.0.0/8", "8.8.8.0/24"), policy) == nets("8.8.8.0/24")


def test_prefix_exactly_at_min_len_kept():
    policy = Guards(min_prefix_len=16)
    assert apply_guards(nets("8.8.0.0/16"), policy) == nets("8.8.0.0/16")


def test_ipv6_uses_same_threshold():
    """Порог общий для обоих семейств: типичный v6-блок провайдера его проходит."""
    policy = Guards(min_prefix_len=10)
    assert apply_guards(nets("2001:4860::/32"), policy) == nets("2001:4860::/32")


def test_ipv6_default_route_dropped():
    assert apply_guards(nets("::/0", "2001:4860::/32"), DEFAULT) == nets("2001:4860::/32")


# --- защита от массового withdraw ---

def test_change_ratio_within_limit_passes():
    policy = Guards(max_change_ratio=0.5)
    previous = nets("8.8.8.0/24", "8.8.4.0/24", "1.1.1.0/24", "1.0.0.0/24")
    current = nets("8.8.8.0/24", "8.8.4.0/24", "1.1.1.0/24")
    assert apply_guards(current, policy, previous=previous) == sorted(current)


def test_change_ratio_exceeded_raises():
    """Резолв упал и принёс два префикса вместо сотни — это не повод снять сотню."""
    policy = Guards(max_change_ratio=0.5)
    previous = nets(*[f"10.{i}.0.0/24" for i in range(100)])
    with pytest.raises(BgpfeedError, match="change"):
        apply_guards(nets("8.8.8.0/24"), policy, previous=previous)


def test_change_ratio_ignored_without_previous():
    """Первый запуск не с чем сравнивать — проверка не должна его блокировать."""
    policy = Guards(max_change_ratio=0.5)
    assert apply_guards(nets("8.8.8.0/24"), policy, previous=None) == nets("8.8.8.0/24")


def test_change_ratio_can_be_disabled_explicitly():
    previous = nets(*[f"10.{i}.0.0/24" for i in range(100)])
    policy = Guards(max_change_ratio=None)
    assert apply_guards(nets("8.8.8.0/24"), policy, previous=previous) == nets("8.8.8.0/24")


def test_growth_is_not_a_change_violation():
    """Ограничение стережёт исчезновение маршрутов, а не их появление."""
    policy = Guards(max_change_ratio=0.5)
    previous = nets("8.8.8.0/24")
    current = nets(*[f"8.{i}.0.0/24" for i in range(100)])
    assert apply_guards(current, policy, previous=previous) == sorted(current)


# --- прочее ---

def test_empty_input_passes_through():
    assert apply_guards([], DEFAULT) == []


def test_mixed_families_do_not_break_sorting():
    """RADB отдаёт route и route6 одним ответом — сортировка обязана это пережить."""
    result = apply_guards(nets("2001:4860::/32", "8.8.8.0/24"), DEFAULT)
    assert result == nets("8.8.8.0/24", "2001:4860::/32")


def test_result_is_sorted_and_deduplicated():
    result = apply_guards(nets("8.8.4.0/24", "8.8.8.0/24", "8.8.4.0/24"), DEFAULT)
    assert result == nets("8.8.4.0/24", "8.8.8.0/24")
