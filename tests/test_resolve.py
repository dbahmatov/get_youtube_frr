"""Тесты резолва с привязкой к точке выхода.

dnspython здесь замокан целиком: живой DNS в юнит-тестах дал бы разные
ответы на разных машинах, а проверять нужно не CDN, а нашу логику вокруг
него.

Ключевое требование, которое здесь стережётся: **частичный сбой резолва не
сокращает анонс**. Если половина хостов не отрезолвилась, мы отдаём то, что
получили, и громко жалуемся — но не делаем вид, что у сервиса стало вдвое
меньше адресов. Обратное поведение приводит к withdraw живых маршрутов из-за
моргнувшего DNS.

Живая проверка биндинга `source_ip` — только на vds-kg: локально у машины
нет того интерфейса, через который ходит продакшн-трафик, и подделать это
мока́ми бессмысленно.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import dns.exception
import dns.resolver

from bgpfeed import resolve
from bgpfeed.config import ResolveConfig, Vantage


class FakeAnswer:
    def __init__(self, addresses):
        self._addresses = addresses

    def __iter__(self):
        return iter(FakeRdata(a) for a in self._addresses)


class FakeRdata:
    def __init__(self, address):
        self.address = address

    def __str__(self):
        return self.address


class FakeResolver:
    """Подменяет dns.resolver.Resolver и записывает, как его настроили."""

    instances = []

    def __init__(self, configure=True):
        self.nameservers = []
        self.lifetime = None
        self.timeout = None
        self.queries = []
        FakeResolver.instances.append(self)

    # поведение задаётся классовыми полями — так тест управляет всеми
    # экземплярами, которые создаст пул потоков
    answers = {}
    raises = {}

    def resolve(self, qname, rdtype, source=None, **kwargs):
        self.queries.append((qname, rdtype, source))
        key = (qname, rdtype)
        if key in FakeResolver.raises:
            raise FakeResolver.raises[key]
        if qname in FakeResolver.raises:
            raise FakeResolver.raises[qname]
        if key not in FakeResolver.answers:
            raise dns.resolver.NXDOMAIN()
        return FakeAnswer(FakeResolver.answers[key])


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    FakeResolver.instances = []
    FakeResolver.answers = {}
    FakeResolver.raises = {}
    monkeypatch.setattr(dns.resolver, "Resolver", FakeResolver)
    yield FakeResolver


def cfg(**kwargs) -> ResolveConfig:
    base = dict(rounds=1, round_delay_sec=0, concurrency=2, timeout_sec=1)
    base.update(kwargs)
    return ResolveConfig(**base)


# --- базовый резолв ---

def test_resolves_a_record(fake_dns):
    fake_dns.answers[("youtube.com", "A")] = ["142.250.1.1"]
    result = resolve.resolve_hostnames(["youtube.com"], cfg(record_types=("A",)))
    assert result.addresses == {"142.250.1.1"}


def test_resolves_both_families(fake_dns):
    fake_dns.answers[("youtube.com", "A")] = ["142.250.1.1"]
    fake_dns.answers[("youtube.com", "AAAA")] = ["2a00:1450::1"]
    result = resolve.resolve_hostnames(["youtube.com"], cfg())
    assert result.addresses == {"142.250.1.1", "2a00:1450::1"}


def test_multiple_answers_all_kept(fake_dns):
    """CDN отдаёт несколько A на имя — нужны все, это разные узлы."""
    fake_dns.answers[("youtube.com", "A")] = ["142.250.1.1", "142.250.1.2"]
    result = resolve.resolve_hostnames(["youtube.com"], cfg(record_types=("A",)))
    assert result.addresses == {"142.250.1.1", "142.250.1.2"}


def test_addresses_attributed_to_hostname(fake_dns):
    fake_dns.answers[("a.com", "A")] = ["1.1.1.1"]
    fake_dns.answers[("b.com", "A")] = ["2.2.2.2"]
    result = resolve.resolve_hostnames(["a.com", "b.com"], cfg(record_types=("A",)))
    assert result.by_hostname["a.com"] == {"1.1.1.1"}
    assert result.by_hostname["b.com"] == {"2.2.2.2"}


def test_empty_hostname_list(fake_dns):
    result = resolve.resolve_hostnames([], cfg())
    assert result.addresses == set()


# --- vantage ---

def test_source_ip_passed_to_query(fake_dns):
    """Биндинг к source_ip — смысл всего модуля: ответ CDN зависит от того,
    откуда пришёл запрос, и должен совпадать с точкой выхода трафика."""
    fake_dns.answers[("youtube.com", "A")] = ["142.250.1.1"]
    vantage = Vantage(source_ip="10.1.2.3")
    resolve.resolve_hostnames(["youtube.com"], cfg(record_types=("A",), vantage=vantage))

    sources = [q[2] for inst in fake_dns.instances for q in inst.queries]
    assert sources and all(s == "10.1.2.3" for s in sources)


def test_no_source_ip_leaves_binding_to_os(fake_dns):
    fake_dns.answers[("youtube.com", "A")] = ["142.250.1.1"]
    resolve.resolve_hostnames(["youtube.com"], cfg(record_types=("A",)))
    sources = [q[2] for inst in fake_dns.instances for q in inst.queries]
    assert all(s is None for s in sources)


def test_custom_resolvers_used(fake_dns):
    fake_dns.answers[("youtube.com", "A")] = ["142.250.1.1"]
    vantage = Vantage(resolvers=["8.8.8.8", "1.1.1.1"])
    resolve.resolve_hostnames(["youtube.com"], cfg(record_types=("A",), vantage=vantage))
    assert any(inst.nameservers == ["8.8.8.8", "1.1.1.1"] for inst in fake_dns.instances)


def test_system_resolver_keyword_leaves_defaults(fake_dns):
    """`system` означает «не трогай nameservers» — берём резолвер хоста."""
    fake_dns.answers[("youtube.com", "A")] = ["142.250.1.1"]
    resolve.resolve_hostnames(["youtube.com"], cfg(record_types=("A",)))
    assert all(inst.nameservers == [] for inst in fake_dns.instances)


# --- накопление по раундам ---

def test_multiple_rounds_accumulate_different_answers(fake_dns):
    """CDN балансирует ответами: несколько раундов дают разные узлы."""
    seen = {"n": 0}

    def rotating(self, qname, rdtype, source=None, **kwargs):
        seen["n"] += 1
        return FakeAnswer([f"142.250.1.{seen['n']}"])

    original = FakeResolver.resolve
    FakeResolver.resolve = rotating
    try:
        result = resolve.resolve_hostnames(
            ["youtube.com"], cfg(record_types=("A",), rounds=3, round_delay_sec=0)
        )
    finally:
        FakeResolver.resolve = original

    assert len(result.addresses) == 3


def test_single_round_by_default(fake_dns):
    fake_dns.answers[("youtube.com", "A")] = ["142.250.1.1"]
    resolve.resolve_hostnames(["youtube.com"], cfg(record_types=("A",), rounds=1))
    total = sum(len(inst.queries) for inst in fake_dns.instances)
    assert total == 1


# --- устойчивость к сбоям ---

def test_nxdomain_does_not_abort_run(fake_dns):
    fake_dns.raises["dead.com"] = dns.resolver.NXDOMAIN()
    fake_dns.answers[("alive.com", "A")] = ["1.1.1.1"]
    result = resolve.resolve_hostnames(["dead.com", "alive.com"], cfg(record_types=("A",)))
    assert result.addresses == {"1.1.1.1"}


def test_timeout_does_not_abort_run(fake_dns):
    fake_dns.raises["slow.com"] = dns.exception.Timeout()
    fake_dns.answers[("alive.com", "A")] = ["1.1.1.1"]
    result = resolve.resolve_hostnames(["slow.com", "alive.com"], cfg(record_types=("A",)))
    assert result.addresses == {"1.1.1.1"}


def test_failures_are_reported(fake_dns):
    fake_dns.raises["dead.com"] = dns.resolver.NXDOMAIN()
    fake_dns.answers[("alive.com", "A")] = ["1.1.1.1"]
    result = resolve.resolve_hostnames(["dead.com", "alive.com"], cfg(record_types=("A",)))
    assert "dead.com" in result.failed
    assert "alive.com" not in result.failed


def test_total_failure_is_visible_not_silent(fake_dns):
    """Резолв не дал ничего — это должно быть видно вызывающему.

    Молчаливый пустой результат неотличим от «у сервиса нет адресов» и
    приводит к снятию всех маршрутов.
    """
    fake_dns.raises["a.com"] = dns.exception.Timeout()
    fake_dns.raises["b.com"] = dns.exception.Timeout()
    result = resolve.resolve_hostnames(["a.com", "b.com"], cfg(record_types=("A",)))
    assert result.addresses == set()
    assert len(result.failed) == 2
    assert result.all_failed is True


def test_partial_success_is_not_all_failed(fake_dns):
    fake_dns.raises["dead.com"] = dns.exception.Timeout()
    fake_dns.answers[("alive.com", "A")] = ["1.1.1.1"]
    result = resolve.resolve_hostnames(["dead.com", "alive.com"], cfg(record_types=("A",)))
    assert result.all_failed is False


def test_no_answer_is_not_a_failure(fake_dns):
    """Хост без AAAA — норма, а не сбой: у него просто нет v6."""
    fake_dns.answers[("youtube.com", "A")] = ["1.1.1.1"]
    fake_dns.raises[("youtube.com", "AAAA")] = dns.resolver.NoAnswer()
    result = resolve.resolve_hostnames(["youtube.com"], cfg())
    assert result.addresses == {"1.1.1.1"}
    assert "youtube.com" not in result.failed


# --- цели резолва ---

def test_targets_include_domains_and_wildcard_samples():
    from bgpfeed.config import Wildcard

    targets = resolve.build_targets(
        domains=("youtubei.googleapis.com",),
        wildcards=(Wildcard(pattern="*.googlevideo.com", samples=("rr1.googlevideo.com",)),),
        known_hostnames=(),
    )
    assert "youtubei.googleapis.com" in targets
    assert "rr1.googlevideo.com" in targets


def test_wildcard_pattern_itself_is_not_a_target():
    """`*.googlevideo.com` нельзя отрезолвить — это шаблон, а не имя."""
    from bgpfeed.config import Wildcard

    targets = resolve.build_targets(
        domains=(),
        wildcards=(Wildcard(pattern="*.googlevideo.com", samples=("rr1.googlevideo.com",)),),
        known_hostnames=(),
    )
    assert "*.googlevideo.com" not in targets


def test_known_hostnames_from_state_are_targets():
    """Накопленное состояние — главный источник целей для wildcard-сервисов."""
    targets = resolve.build_targets(
        domains=(), wildcards=(), known_hostnames=("rr2.googlevideo.com",),
    )
    assert "rr2.googlevideo.com" in targets


def test_targets_deduplicated():
    targets = resolve.build_targets(
        domains=("a.com",), wildcards=(), known_hostnames=("a.com",),
    )
    assert targets.count("a.com") == 1
