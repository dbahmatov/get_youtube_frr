"""Тесты выгрузки префиксов из IRR (RADB).

Два независимых предмета проверки:

* **Парсер** — на реальных снимках whois. Он обязан вытаскивать route и
  route6, игнорировать все прочие атрибуты и не давиться RPKI-дубликатами.
* **Вызов whois** — аргументы передаются списком. Старый код собирал команду
  f-строкой и запускал через `shell=True`, где номер ASN подставлялся прямо
  в строку.
"""

import gzip
import ipaddress
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from bgpfeed import irr
from bgpfeed.errors import FetchError

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture_text(name: str) -> str:
    path = os.path.join(FIXTURES, name)
    opener = gzip.open if name.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def net(cidr):
    return ipaddress.ip_network(cidr)


# --- парсер ---

def test_parses_route_objects():
    result = irr.parse_route_objects(fixture_text("radb_as36561.txt"))
    assert result == [net("165.85.150.0/24")]


def test_duplicate_route_objects_deduplicated():
    """RADB отдаёт один и тот же префикс из IRR и из RPKI-конверсии."""
    text = fixture_text("radb_as36561.txt")
    assert text.count("route:") > 1
    assert len(irr.parse_route_objects(text)) == 1


def test_parses_large_snapshot():
    result = irr.parse_route_objects(fixture_text("radb_as15169.txt.gz"))
    assert len(result) == 1831


def test_parses_route6():
    text = "route6:         2001:4860::/32\norigin:         AS15169\n"
    assert irr.parse_route_objects(text) == [net("2001:4860::/32")]


def test_ignores_other_attributes():
    text = (
        "route:          8.8.8.0/24\n"
        "descr:          not-a-prefix 1.2.3.4/32\n"
        "origin:         AS15169\n"
        "mnt-by:         MAINT-AS15169\n"
    )
    assert irr.parse_route_objects(text) == [net("8.8.8.0/24")]


def test_malformed_prefix_skipped():
    text = "route:          999.999.999.0/24\nroute:          8.8.8.0/24\n"
    assert irr.parse_route_objects(text) == [net("8.8.8.0/24")]


def test_empty_text_yields_nothing():
    assert irr.parse_route_objects("") == []


def test_result_is_sorted():
    text = "route:          8.8.8.0/24\nroute:          1.1.1.0/24\n"
    assert irr.parse_route_objects(text) == [net("1.1.1.0/24"), net("8.8.8.0/24")]


def test_mixed_families_in_one_answer():
    """Обычный ответ RADB содержит и route, и route6 — сравнивать их напрямую нельзя."""
    text = "route6:         2001:4860::/32\nroute:          8.8.8.0/24\n"
    assert irr.parse_route_objects(text) == [net("8.8.8.0/24"), net("2001:4860::/32")]


# --- покрывающий префикс ---

def test_covering_prefix_picks_most_specific():
    """Из /12 и /24 берётся /24: он стоит того же маршрута, но не тащит чужое."""
    pool = [net("8.0.0.0/12"), net("8.8.8.0/24"), net("1.1.1.0/24")]
    assert irr.covering_prefix("8.8.8.8", pool) == net("8.8.8.0/24")


def test_covering_prefix_none_when_uncovered():
    assert irr.covering_prefix("9.9.9.9", [net("8.8.8.0/24")]) is None


def test_covering_prefix_ignores_other_family():
    pool = [net("2001:4860::/32"), net("8.8.8.0/24")]
    assert irr.covering_prefix("8.8.8.8", pool) == net("8.8.8.0/24")


def test_covering_prefix_ipv6():
    pool = [net("2001:4860::/32"), net("2001:4860:4860::/48")]
    assert irr.covering_prefix("2001:4860:4860::8888", pool) == net("2001:4860:4860::/48")


def test_covering_prefix_empty_pool():
    assert irr.covering_prefix("8.8.8.8", []) is None


# --- вызов whois ---

class FakeRun:
    """Подменяет subprocess.run и запоминает, чем его звали."""

    def __init__(self, stdout="", returncode=0, exc=None):
        self.stdout = stdout
        self.returncode = returncode
        self.exc = exc
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if self.exc is not None:
            raise self.exc
        return subprocess.CompletedProcess(args, self.returncode, self.stdout, "")


def test_whois_called_without_shell(monkeypatch):
    fake = FakeRun(stdout="route: 8.8.8.0/24\n")
    monkeypatch.setattr(subprocess, "run", fake)
    irr.fetch_prefixes(15169)

    args, kwargs = fake.calls[0]
    assert isinstance(args, list), "команда обязана передаваться списком"
    assert kwargs.get("shell") in (None, False)


def test_whois_query_targets_the_asn(monkeypatch):
    fake = FakeRun(stdout="route: 8.8.8.0/24\n")
    monkeypatch.setattr(subprocess, "run", fake)
    irr.fetch_prefixes(15169)

    args, _ = fake.calls[0]
    assert args[0] == "whois"
    assert any("AS15169" in part for part in args)
    # Запрос обязан быть одним аргументом: разбитый на части, он теряет `-i`.
    assert any(part == "-i origin AS15169" for part in args)


def test_asn_is_not_interpolated_as_text(monkeypatch):
    """ASN уже провалидирован конфигом, но в команду он идёт числом."""
    fake = FakeRun(stdout="")
    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(FetchError, match="AS"):
        irr.fetch_prefixes("15169; rm -rf /")
    assert fake.calls == []


def test_fetch_returns_parsed_prefixes(monkeypatch):
    monkeypatch.setattr(subprocess, "run", FakeRun(stdout=fixture_text("radb_as36561.txt")))
    assert irr.fetch_prefixes(36561) == [net("165.85.150.0/24")]


def test_whois_failure_raises(monkeypatch):
    """Недоступный RADB — это ошибка, а не пустой список.

    Пустой список означал бы «у ASN нет префиксов» и увёл бы дальше по
    конвейеру в массовый withdraw.
    """
    monkeypatch.setattr(subprocess, "run", FakeRun(stdout="", returncode=1))
    with pytest.raises(FetchError):
        irr.fetch_prefixes(15169)


def test_whois_timeout_raises(monkeypatch):
    exc = subprocess.TimeoutExpired(cmd=["whois"], timeout=30)
    monkeypatch.setattr(subprocess, "run", FakeRun(exc=exc))
    with pytest.raises(FetchError, match="timeout"):
        irr.fetch_prefixes(15169)


def test_whois_missing_binary_raises(monkeypatch):
    monkeypatch.setattr(subprocess, "run", FakeRun(exc=FileNotFoundError("whois")))
    with pytest.raises(FetchError, match="whois"):
        irr.fetch_prefixes(15169)


def test_empty_answer_raises(monkeypatch):
    """ASN без единого route-объекта подозрителен: whois ответил, но пусто."""
    monkeypatch.setattr(subprocess, "run", FakeRun(stdout="%  No entries found\n"))
    with pytest.raises(FetchError, match="no route objects"):
        irr.fetch_prefixes(15169)
