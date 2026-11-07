"""Тесты сборки конвейера обнаружения.

Внешние источники подменяются целиком: проверяется склейка, а не DNS, Cymru
и RADB по отдельности — у каждого из них свой файл тестов.

Главное, что здесь стережётся, — что стратегия применяется по месту:
дешёвая ASN разворачивается целиком, дорогая даёт только блоки вокруг наших
адресов, а сервис без доменов ведёт себя ровно как в v1.
"""

import ipaddress
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from bgpfeed import discover
from bgpfeed.asnmap.cymru import AsnRecord
from bgpfeed.config import AsnPolicy, Budget, Guards, Service, Wildcard
from bgpfeed.errors import FetchError
from bgpfeed.resolve import ResolveResult
from bgpfeed.state import State


def net(cidr):
    return ipaddress.ip_network(cidr)


class Sources:
    """Заглушки внешних источников с настраиваемыми ответами."""

    def __init__(self):
        self.resolved = {}
        self.cymru = {}
        self.irr = {}
        self.irr_calls = []
        self.resolve_calls = []

    def resolve(self, hostnames, config):
        self.resolve_calls.append(list(hostnames))
        result = ResolveResult()
        for hostname in hostnames:
            addresses = self.resolved.get(hostname)
            if addresses:
                result.by_hostname[hostname] = set(addresses)
            else:
                result.failed[hostname] = "NXDOMAIN"
        return result

    def lookup(self, addresses):
        return {ip: self.cymru.get(ip, AsnRecord(ip=ip)) for ip in addresses}

    def fetch(self, asn):
        self.irr_calls.append(asn)
        if asn not in self.irr:
            raise FetchError(f"no route objects for AS{asn}")
        return list(self.irr[asn])


@pytest.fixture
def sources():
    return Sources()


def service(**kwargs) -> Service:
    base = dict(
        name="youtube",
        domains=("youtube.com",),
        strategy="hybrid",
        asn_policy=AsnPolicy(),
    )
    base.update(kwargs)
    return Service(**base)


def run(svc, sources, state=None, budget=None, guards=None):
    return discover.discover_service(
        svc,
        state=state or State(),
        budget=budget or Budget(max_total_prefixes=20000),
        guards=guards or Guards(),
        resolve_fn=sources.resolve,
        lookup_fn=sources.lookup,
        fetch_fn=sources.fetch,
    )


# --- сквозной путь ---

def test_resolved_ip_leads_to_its_asn(sources):
    sources.resolved["youtube.com"] = ["142.250.1.1"]
    sources.cymru["142.250.1.1"] = AsnRecord("142.250.1.1", 15169, net("142.250.1.0/24"))
    sources.irr[15169] = [net("142.250.0.0/16")]

    report = run(service(), sources)
    assert 15169 in {v.asn for v in report.verdicts}


def test_trusted_asn_expands_from_irr(sources):
    """Дешёвая ASN разворачивается целиком: её лишние префиксы безвредны."""
    sources.resolved["youtube.com"] = ["142.250.1.1"]
    sources.cymru["142.250.1.1"] = AsnRecord("142.250.1.1", 15169, net("142.250.1.0/24"))
    sources.irr[15169] = [net("142.250.0.0/16"), net("172.217.0.0/16")]

    report = run(service(), sources)
    assert net("172.217.0.0/16") in report.prefixes


def test_explicit_covering_strategy_yields_only_covering_prefixes(sources):
    """Только явная стратегия может запросить узкое покрытие."""
    sources.resolved["youtube.com"] = ["52.1.1.1"]
    sources.cymru["52.1.1.1"] = AsnRecord("52.1.1.1", 16509, net("52.1.1.0/24"))
    sources.irr[16509] = [net(f"52.{i}.0.0/16") for i in range(1, 200)]

    report = run(service(strategy="covering_prefix"), sources)
    assert report.prefixes == [net("52.1.1.0/24")]


def test_explicit_covering_strategy_falls_back_to_irr_without_cymru_prefix(sources):
    """Cymru не назвал блок — ищем покрывающий в RADB, а не теряем адрес."""
    sources.resolved["youtube.com"] = ["52.1.1.1"]
    sources.cymru["52.1.1.1"] = AsnRecord("52.1.1.1", 16509, None)
    sources.irr[16509] = [net("52.1.0.0/16"), net("53.0.0.0/12")]

    report = run(service(strategy="covering_prefix"), sources)
    assert report.prefixes == [net("52.1.0.0/16")]
    assert sources.irr_calls == [16509]


def test_covering_strategy_skips_irr_when_cymru_has_all_prefixes(sources):
    """Широкий RADB не нужен, если каждый observed IP уже покрыт ответом Cymru."""
    sources.resolved["youtube.com"] = ["52.1.1.1", "52.2.2.2"]
    sources.cymru["52.1.1.1"] = AsnRecord("52.1.1.1", 16509, net("52.1.1.0/24"))
    sources.cymru["52.2.2.2"] = AsnRecord("52.2.2.2", 16509, net("52.2.2.0/24"))

    report = run(service(strategy="covering_prefix"), sources)

    assert sources.irr_calls == []
    assert report.prefixes == [net("52.1.1.0/24"), net("52.2.2.0/24")]


def test_rejected_asn_contributes_nothing(sources):
    sources.resolved["youtube.com"] = ["1.2.3.4"]
    sources.cymru["1.2.3.4"] = AsnRecord("1.2.3.4", 64500, net("1.2.3.0/24"))
    sources.irr[64500] = [net("1.2.0.0/16")]

    policy = AsnPolicy(exclude_asns=(64500,))
    report = run(service(asn_policy=policy), sources)
    assert report.prefixes == []


def test_unrouted_address_is_ignored(sources):
    """Адрес, который никто не анонсирует, не превращается в маршрут."""
    sources.resolved["youtube.com"] = ["192.0.2.1"]
    sources.cymru["192.0.2.1"] = AsnRecord("192.0.2.1", None, None)
    report = run(service(), sources)
    assert report.prefixes == []


# --- цели резолва ---

def test_wildcard_samples_are_resolved(sources):
    sources.resolved["rr1.googlevideo.com"] = ["142.250.1.1"]
    sources.cymru["142.250.1.1"] = AsnRecord("142.250.1.1", 15169, net("142.250.1.0/24"))
    sources.irr[15169] = [net("142.250.0.0/16")]

    svc = service(domains=(), wildcards=(
        Wildcard(pattern="*.googlevideo.com", samples=("rr1.googlevideo.com",)),
    ))
    run(svc, sources)
    assert "rr1.googlevideo.com" in sources.resolve_calls[0]


def test_hostnames_from_state_are_resolved(sources):
    """Накопленное за прошлые прогоны — основной источник целей для wildcard."""
    state = State()
    state.observe("youtube", hostnames=["rr7.googlevideo.com"])
    sources.resolved["rr7.googlevideo.com"] = ["142.250.1.1"]
    sources.cymru["142.250.1.1"] = AsnRecord("142.250.1.1", 15169, net("142.250.1.0/24"))
    sources.irr[15169] = [net("142.250.0.0/16")]

    run(service(domains=()), sources, state=state)
    assert "rr7.googlevideo.com" in sources.resolve_calls[0]


def test_new_observations_are_recorded_in_state(sources):
    state = State()
    sources.resolved["youtube.com"] = ["142.250.1.1"]
    sources.cymru["142.250.1.1"] = AsnRecord("142.250.1.1", 15169, net("142.250.1.0/24"))
    sources.irr[15169] = [net("142.250.0.0/16")]

    run(service(), sources, state=state)
    assert "142.250.1.1" in state.addresses("youtube")
    assert 15169 in state.asns("youtube")


def test_previously_observed_asn_keeps_full_coverage(sources):
    """Смена CDN-ответа не должна отзывать ещё живую ASN из state."""
    state = State()
    state.observe("youtube", asns=(16509,))
    sources.resolved["youtube.com"] = ["142.250.1.1"]
    sources.cymru["142.250.1.1"] = AsnRecord(
        "142.250.1.1", 15169, net("142.250.1.0/24"),
    )
    sources.irr[15169] = [net("142.250.0.0/16")]
    sources.irr[16509] = [net("52.0.0.0/11")]

    report = run(service(), sources, state=state)

    assert report.prefixes == [net("52.0.0.0/11"), net("142.250.0.0/16")]
    assert {verdict.asn for verdict in report.verdicts} == {15169, 16509}


def test_historical_asn_is_not_refreshed_without_current_record(sources):
    """Запись в state сама по себе не должна продлевать собственный TTL."""
    state = State()
    state.observe("youtube", asns=(16509,), now=0)
    sources.resolved["youtube.com"] = ["142.250.1.1"]
    sources.cymru["142.250.1.1"] = AsnRecord(
        "142.250.1.1", 15169, net("142.250.1.0/24"),
    )
    sources.irr[15169] = [net("142.250.0.0/16")]
    sources.irr[16509] = [net("52.0.0.0/11")]

    run(service(), sources, state=state)

    assert state.age_days("youtube", "asns", "16509") > 1


def test_covering_strategy_keeps_historical_state_addresses(sources):
    """Старый CDN-IP покрывается до TTL, даже если DNS уже отдал другой."""
    state = State()
    state.observe("youtube", addresses=("52.1.1.1",))
    sources.resolved["youtube.com"] = ["142.250.1.1"]
    sources.cymru["52.1.1.1"] = AsnRecord(
        "52.1.1.1", 16509, net("52.1.1.0/24"),
    )
    sources.cymru["142.250.1.1"] = AsnRecord(
        "142.250.1.1", 15169, net("142.250.1.0/24"),
    )
    sources.irr[15169] = [net("142.250.0.0/16")]
    sources.irr[16509] = [net("52.0.0.0/11")]

    report = run(service(strategy="covering_prefix"), sources, state=state)

    assert report.prefixes == [net("52.1.1.0/24"), net("142.250.1.0/24")]


# --- ручные ASN ---

def test_manual_asn_included_without_any_resolve(sources):
    """v1-сервис: доменов нет, ASN заданы руками — работает как раньше."""
    sources.irr[36561] = [net("165.85.150.0/24")]
    svc = service(domains=(), as_numbers=(36561,), strategy="asn",
                  asn_policy=AsnPolicy(trusted_asns=(36561,)))
    report = run(svc, sources)
    assert report.prefixes == [net("165.85.150.0/24")]


def test_asn_strategy_skips_resolution(sources):
    sources.irr[36561] = [net("165.85.150.0/24")]
    svc = service(domains=("youtube.com",), as_numbers=(36561,), strategy="asn",
                  asn_policy=AsnPolicy(trusted_asns=(36561,)))
    run(svc, sources)
    assert sources.resolve_calls == []


def test_covering_strategy_keeps_manual_asn_fully_expanded(sources):
    """У ручной ASN нет observed IP, поэтому limited стёр бы всё покрытие."""
    sources.irr[36561] = [net("165.85.150.0/24"), net("172.16.0.0/16")]
    svc = service(domains=(), as_numbers=(36561,), strategy="covering_prefix",
                  asn_policy=AsnPolicy(trusted_asns=(36561,)))

    report = run(svc, sources, guards=Guards(drop_bogons=False))

    assert report.prefixes == [net("165.85.150.0/24"), net("172.16.0.0/16")]


def test_manual_asn_survives_being_expensive(sources):
    # /12, а не /8: guards отбрасывают всё шире /10, и тест мерил бы не то.
    sources.irr[36561] = [net(f"10{i}.0.0.0/12") for i in range(1, 5)]
    svc = service(domains=(), as_numbers=(36561,), strategy="asn",
                  asn_policy=AsnPolicy(trusted_asns=(36561,)))
    report = run(svc, sources)
    assert len(report.prefixes) == 4


# --- устойчивость ---

def test_irr_failure_without_address_fallback_raises(sources):
    """Ручная ASN без RADB и observed IP иначе молча исчезнет из desired."""
    svc = service(domains=(), as_numbers=(36561,), strategy="asn",
                  asn_policy=AsnPolicy(trusted_asns=(36561,)))

    with pytest.raises(FetchError, match="36561"):
        run(svc, sources)


def test_irr_failure_does_not_kill_the_run(sources):
    """RADB не знает одну ASN — остальные всё равно должны доехать."""
    sources.resolved["youtube.com"] = ["142.250.1.1", "203.0.113.9"]
    sources.cymru["142.250.1.1"] = AsnRecord("142.250.1.1", 15169, net("142.250.1.0/24"))
    sources.cymru["203.0.113.9"] = AsnRecord("203.0.113.9", 64500, net("203.0.113.0/24"))
    sources.irr[15169] = [net("142.250.0.0/16")]

    report = run(service(), sources)
    assert net("142.250.0.0/16") in report.prefixes


def test_asn_without_irr_data_still_covers_its_addresses(sources):
    """Нет данных в RADB — берём хотя бы блок от Cymru, а не бросаем адрес."""
    sources.resolved["youtube.com"] = ["203.0.113.9"]
    sources.cymru["203.0.113.9"] = AsnRecord("203.0.113.9", 64500, net("203.0.113.0/24"))

    report = run(service(), sources, guards=Guards(drop_bogons=False))
    assert net("203.0.113.0/24") in report.prefixes


def test_resolve_failure_is_visible_in_report(sources):
    report = run(service(), sources)
    assert report.resolve_failed
    assert report.prefixes == []


def test_irr_queried_once_per_asn(sources):
    """Две ASN на десять адресов — два запроса в RADB, а не десять."""
    for i in range(5):
        sources.resolved[f"h{i}.youtube.com"] = [f"142.250.1.{i}"]
        sources.cymru[f"142.250.1.{i}"] = AsnRecord(
            f"142.250.1.{i}", 15169, net("142.250.1.0/24")
        )
    sources.irr[15169] = [net("142.250.0.0/16")]

    svc = service(domains=tuple(f"h{i}.youtube.com" for i in range(5)))
    run(svc, sources)
    assert sources.irr_calls.count(15169) == 1


# --- бюджет и защиты ---

def test_guards_applied_to_result(sources):
    sources.resolved["youtube.com"] = ["10.1.1.1"]
    sources.cymru["10.1.1.1"] = AsnRecord("10.1.1.1", 64500, net("10.1.1.0/24"))
    sources.irr[64500] = [net("10.0.0.0/8")]

    report = run(service(), sources)
    assert report.prefixes == []


def test_result_is_summarized(sources):
    sources.resolved["youtube.com"] = ["142.250.1.1"]
    sources.cymru["142.250.1.1"] = AsnRecord("142.250.1.1", 15169, net("142.250.1.0/24"))
    sources.irr[15169] = [net("142.250.0.0/25"), net("142.250.0.128/25")]

    report = run(service(), sources)
    assert report.prefixes == [net("142.250.0.0/24")]


def test_collapsed_prefix_too_wide_keeps_specific_parts(sources):
    """Guard не должен выбрасывать корректные /10 после склейки в /9."""
    sources.resolved["youtube.com"] = ["8.8.8.8"]
    sources.cymru["8.8.8.8"] = AsnRecord("8.8.8.8", 15169, net("8.8.8.0/24"))
    sources.irr[15169] = [net("8.0.0.0/10"), net("8.64.0.0/10")]

    report = run(service(), sources, guards=Guards(min_prefix_len=10))

    assert report.prefixes == [net("8.0.0.0/10"), net("8.64.0.0/10")]


def test_radb_cost_reuses_the_collapsed_set(sources):
    """Повторный summarize уже готового набора лишний и ломает one-shot вход."""
    sources.resolved["youtube.com"] = ["142.250.1.1"]
    sources.cymru["142.250.1.1"] = AsnRecord("142.250.1.1", 15169, net("142.250.1.0/24"))

    report = discover.discover_service(
        service(),
        state=State(),
        budget=Budget(max_total_prefixes=20000),
        guards=Guards(),
        resolve_fn=sources.resolve,
        lookup_fn=sources.lookup,
        fetch_fn=lambda asn: iter([net("142.250.0.0/16")]),
    )

    assert report.verdicts[0].prefix_count == 1


def test_budget_overflow_keeps_full_collapsed_prefixes(sources):
    sources.resolved["youtube.com"] = ["52.1.1.1"]
    sources.cymru["52.1.1.1"] = AsnRecord("52.1.1.1", 16509, net("52.1.1.0/24"))
    sources.irr[16509] = [net(f"52.{i}.0.0/16") for i in range(1, 100)]

    report = run(service(), sources, budget=Budget(max_total_prefixes=5))
    assert len(report.prefixes) == 8
    assert report.verdicts[0].tier == "trusted"


def test_report_explains_every_asn(sources):
    """`show asns` печатает это — на каждую ASN должно быть обоснование."""
    sources.resolved["youtube.com"] = ["142.250.1.1"]
    sources.cymru["142.250.1.1"] = AsnRecord("142.250.1.1", 15169, net("142.250.1.0/24"))
    sources.irr[15169] = [net("142.250.0.0/16")]

    report = run(service(), sources)
    assert all(v.reason.strip() for v in report.verdicts)


# --- фиды в конвейере ---
#
# geosite снимает необходимость вести домены руками: в живом фиде категория
# `youtube` — это 178 записей против 19, которые пришлось выписывать вручную
# для проверки на vds-kg. geoip даёт второй признак доверия и собственные
# префиксы.

from bgpfeed.config import GeoipRef, GeositeRef


def feeds_from(mapping):
    """Загрузчик фидов: (kind, category) -> текст."""
    def load(kind, category):
        try:
            return mapping[(kind, category)]
        except KeyError:
            raise FetchError(f"no such category: {kind}:{category}")

    return load


def run_with_feeds(svc, sources, feeds_fn, **kwargs):
    return discover.discover_service(
        svc,
        state=kwargs.get("state") or State(),
        budget=kwargs.get("budget") or Budget(max_total_prefixes=20000),
        guards=kwargs.get("guards") or Guards(),
        resolve_fn=sources.resolve,
        lookup_fn=sources.lookup,
        fetch_fn=sources.fetch,
        feeds_fn=feeds_fn,
    )


def test_geosite_domains_are_resolved(sources):
    sources.resolved["googlevideo.com"] = ["142.250.1.1"]
    sources.cymru["142.250.1.1"] = AsnRecord("142.250.1.1", 15169, net("142.250.1.0/24"))
    sources.irr[15169] = [net("142.250.0.0/16")]

    svc = service(domains=(), geosite=GeositeRef(categories=("youtube",)))
    run_with_feeds(svc, sources, feeds_from({("geosite", "youtube"): "googlevideo.com\n"}))
    assert "googlevideo.com" in sources.resolve_calls[0]


def test_geosite_full_entries_become_targets(sources):
    svc = service(domains=(), geosite=GeositeRef(categories=("youtube",)))
    run_with_feeds(svc, sources,
                   feeds_from({("geosite", "youtube"): "full:www.youtube.com\n"}))
    assert "www.youtube.com" in sources.resolve_calls[0]


def test_geosite_complements_manual_domains(sources):
    """Решение заказчика: «geosite + ручные дополняют», а не заменяют."""
    svc = service(domains=("manual.example",), geosite=GeositeRef(categories=("youtube",)))
    run_with_feeds(svc, sources, feeds_from({("geosite", "youtube"): "feed.example\n"}))
    assert {"manual.example", "feed.example"} <= set(sources.resolve_calls[0])


def test_missing_geosite_category_falls_back_to_manual_domains(sources):
    """Фид переехал — работаем на ручных доменах, а не падаем."""
    sources.resolved["manual.example"] = ["142.250.1.1"]
    sources.cymru["142.250.1.1"] = AsnRecord("142.250.1.1", 15169, net("142.250.1.0/24"))
    sources.irr[15169] = [net("142.250.0.0/16")]

    svc = service(domains=("manual.example",), geosite=GeositeRef(categories=("gone",)))
    report = run_with_feeds(svc, sources, feeds_from({}))
    assert report.prefixes


def test_geoip_corroboration_keeps_full_coverage(sources):
    """Подтверждение остаётся признаком в отчёте, но не урезает набор."""
    sources.resolved["youtube.com"] = ["142.250.1.1"]
    sources.cymru["142.250.1.1"] = AsnRecord("142.250.1.1", 15169, net("142.250.1.0/24"))
    sources.irr[15169] = [net(f"142.{i}.0.0/16") for i in range(1, 30)]

    svc = service(geoip=GeoipRef(categories=("google",), mode="corroborate"))
    report = run_with_feeds(svc, sources,
                            feeds_from({("geoip", "google"): "142.250.0.0/16\n"}))
    assert report.verdicts[0].tier == "trusted"


def test_geoip_announce_mode_contributes_prefixes(sources):
    """Роль 1: CIDR из категории идут в анонс наравне с RADB."""
    svc = service(domains=(), as_numbers=(), strategy="hybrid",
                  geoip=GeoipRef(categories=("google",), mode="announce"))
    report = run_with_feeds(svc, sources,
                            feeds_from({("geoip", "google"): "136.22.2.0/23\n"}))
    assert net("136.22.2.0/23") in report.prefixes


def test_geoip_announce_mode_rejects_partial_category_failure(sources):
    """Доступная категория не должна маскировать потерю маршрутов другой."""
    svc = service(domains=(), as_numbers=(), strategy="hybrid",
                  geoip=GeoipRef(categories=("google", "gone"), mode="announce"))

    with pytest.raises(FetchError, match="gone"):
        run_with_feeds(
            svc, sources, feeds_from({("geoip", "google"): "8.8.8.0/24\n"}),
        )


def test_geoip_corroborate_mode_announces_nothing(sources):
    svc = service(domains=(), as_numbers=(), strategy="hybrid",
                  geoip=GeoipRef(categories=("google",), mode="corroborate"))
    report = run_with_feeds(svc, sources,
                            feeds_from({("geoip", "google"): "136.22.2.0/23\n"}))
    assert report.prefixes == []


def test_geoip_prefixes_pass_through_guards(sources):
    """Чужой список не получает поблажек: bogon отсекается и здесь."""
    svc = service(domains=(), as_numbers=(), strategy="hybrid",
                  geoip=GeoipRef(categories=("google",), mode="announce"))
    report = run_with_feeds(svc, sources,
                            feeds_from({("geoip", "google"): "10.0.0.0/8\n8.8.8.0/24\n"}))
    assert report.prefixes == [net("8.8.8.0/24")]


def test_geoip_announce_keeps_full_coverage_when_over_budget(sources):
    svc = service(domains=(), as_numbers=(), strategy="hybrid",
                  geoip=GeoipRef(categories=("google",), mode="announce"))
    feed = "\n".join(f"8.{i}.0.0/16" for i in range(0, 100)) + "\n"
    report = run_with_feeds(svc, sources, feeds_from({("geoip", "google"): feed}),
                            budget=Budget(max_total_prefixes=10))
    assert report.prefixes == [
        net("8.0.0.0/10"), net("8.64.0.0/11"), net("8.96.0.0/14"),
    ]
    assert report.feed_verdicts[0].mode == "announce"


def test_geoip_over_budget_still_announces_and_corroborates(sources):
    """Превышение бюджета не меняет ни одну роль geoip-категории."""
    sources.resolved["youtube.com"] = ["8.8.8.8"]
    sources.cymru["8.8.8.8"] = AsnRecord("8.8.8.8", 15169, net("8.8.8.0/24"))
    sources.irr[15169] = [net(f"9.{i}.0.0/16") for i in range(1, 30)]

    feed = "\n".join(f"8.{i}.0.0/16" for i in range(100)) + "\n"
    svc = service(geoip=GeoipRef(categories=("google",), mode="announce"))
    report = run_with_feeds(svc, sources, feeds_from({("geoip", "google"): feed}),
                            budget=Budget(max_total_prefixes=40))
    assert report.verdicts[0].tier == "trusted"
    assert report.feed_verdicts[0].mode == "announce"


def test_service_without_feeds_never_calls_the_loader(sources):
    """Сервис без geosite/geoip не должен тянуть списки впустую."""
    calls = []

    def loader(kind, category):
        calls.append((kind, category))
        return ""

    sources.irr[36561] = [net("165.85.150.0/24")]
    svc = service(domains=(), as_numbers=(36561,), strategy="asn",
                  asn_policy=AsnPolicy(trusted_asns=(36561,)))
    run_with_feeds(svc, sources, loader)
    assert calls == []
