"""Конвейер обнаружения: домены → адреса → ASN → префиксы.

Порядок шагов и есть ответ на исходный вопрос «как это будет работать для
любого сервиса»:

1. Собрать цели: домены из конфига, `samples` шаблонов и всё, что накопило
   состояние за прошлые прогоны.
2. Отрезолвить их с точки выхода трафика — так в ответах окажутся
   провайдерский GGC и те узлы CDN, к которым реально пойдёт трафик.
3. Спросить у Cymru, кому принадлежат адреса. Заодно получить покрывающий
   блок каждого адреса — бесплатно, тем же ответом.
4. Получить полный набор каждой ASN из IRR и точно схлопнуть его.
5. Измерить общий размер для наблюдаемого бюджета, не урезая покрытие.
6. Объединить источники, ещё раз точно схлопнуть и проверить защитами.

Ни на одном шаге нет ничего специфичного для YouTube — только измерения.

Внешние источники передаются параметрами: так конвейер тестируется без
сети, а живые прогоны на роутере используют настоящие модули.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Set

from loguru import logger

from . import frr  # noqa: F401  (импорт держит модуль рядом для CLI)
from . import irr, resolve
from .asnmap import cymru
from .asnmap.cymru import AsnRecord
from .budget import FeedVerdict, fit_all
from .config import Budget, Guards, Service
from .errors import FetchError
from .feeds import geoip as geoip_feed
from .feeds import geosite as geosite_feed
from .guards import apply_guards
from .select import AsnVerdict, classify_all
from .state import State
from .summarize import Network, prefix_count, summarize, sort_key


@dataclass
class ServiceReport:
    """Что решено по сервису и почему.

    Хранит не только итоговые префиксы, но и обоснование по каждой ASN:
    без него анонс — чёрный ящик, а разбираться в нём приходится тогда,
    когда что-то уже сломалось.
    """

    service: str
    prefixes: List[Network] = field(default_factory=list)
    verdicts: List[AsnVerdict] = field(default_factory=list)
    addresses: Set[str] = field(default_factory=set)
    resolve_failed: Dict[str, str] = field(default_factory=dict)
    unreachable_asns: Dict[int, str] = field(default_factory=dict)
    feed_verdicts: List[FeedVerdict] = field(default_factory=list)
    corroborated_asns: Set[int] = field(default_factory=set)
    missing_categories: Set[str] = field(default_factory=set)


def discover_service(
    service: Service,
    state: State,
    budget: Budget,
    guards: Guards,
    resolve_fn: Optional[Callable] = None,
    lookup_fn: Optional[Callable] = None,
    fetch_fn: Optional[Callable] = None,
    feeds_fn: Optional[Callable[[str, str], str]] = None,
) -> ServiceReport:
    """Проходит конвейер для одного сервиса.

    `feeds_fn(kind, category)` отдаёт текст списка (`kind` — `geosite` или
    `geoip`). Загрузчик один на оба вида: так конвейер не знает ни про кэш,
    ни про сеть, а тесты подставляют словарь.
    """
    resolve_fn = resolve_fn or resolve.resolve_hostnames
    lookup_fn = lookup_fn or cymru.lookup
    fetch_fn = fetch_fn or irr.fetch_prefixes

    report = ServiceReport(service=service.name)

    extra_targets = _geosite_targets(service, report, feeds_fn)
    records = _discover_addresses(service, state, report, resolve_fn, lookup_fn,
                                  extra_targets)
    observed = _group_by_asn(service, records)
    for asn in state.asns(service.name):
        observed.setdefault(asn, set())

    feed_prefixes = _geoip_prefixes(service, report, budget, feeds_fn)
    report.corroborated_asns = geoip_feed.corroborated_asns(observed, feed_prefixes.prefixes)
    feed_verdicts = _feed_verdicts(service, feed_prefixes, report.addresses)

    if not observed and not feed_verdicts:
        logger.warning("{}: no ASN discovered", service.name)
        return report

    if observed:
        state.observe(service.name, asns=service.as_numbers, manual=True)
        state.observe(service.name,
                      asns=[a for a in observed if a not in service.as_numbers])

    irr_prefixes, costs = _measure_asns(observed, report, fetch_fn)
    verdicts = classify_all(observed, costs, service.asn_policy,
                            corroborated_asns=report.corroborated_asns)
    verdicts = _apply_strategy(service, verdicts)
    verdicts, feed_verdicts = fit_all(verdicts, feed_verdicts, budget,
                                      manual_asns=service.as_numbers)
    report.verdicts = verdicts
    report.feed_verdicts = feed_verdicts

    collected = _collect_prefixes(verdicts, records, irr_prefixes)
    for feed in feed_verdicts:
        if feed.mode == "announce":
            collected.extend(feed_prefixes.by_category.get(feed.category, []))

    report.prefixes = apply_guards(summarize(collected), guards)
    logger.info("{}: {} prefix(es) from {} ASN(s)",
                service.name, len(report.prefixes), len(verdicts))
    return report


def _geosite_targets(
    service: Service,
    report: ServiceReport,
    feeds_fn: Optional[Callable[[str, str], str]],
) -> List[str]:
    """Имена из geosite-категорий сервиса.

    Список дополняет ручные домены, а не заменяет их: категория `youtube` —
    это 178 записей против 19, которые пришлось выписывать руками, но и в
    ручных может быть то, чего в фиде нет.
    """
    if service.geosite is None or feeds_fn is None:
        return []

    result = geosite_feed.GeositeResult()
    for category in service.geosite.categories:
        geosite_feed.load_category(
            category,
            lambda name: feeds_fn("geosite", name),
            exclude_domains=service.geosite.exclude_domains,
            result=result,
        )
    report.missing_categories |= result.missing
    return sorted(result.all_names)


def _geoip_prefixes(
    service: Service,
    report: ServiceReport,
    budget: Budget,
    feeds_fn: Optional[Callable[[str, str], str]],
) -> geoip_feed.GeoipResult:
    """Префиксы geoip-категорий сервиса.

    Загружаются и при `mode: corroborate`: подтверждение ASN — вторая роль
    списка и она не зависит от того, анонсируем мы его или нет.
    """
    if service.geoip is None or feeds_fn is None or service.geoip.mode == "off":
        return geoip_feed.GeoipResult()

    result = geoip_feed.load_categories(
        service.geoip.categories,
        lambda name: feeds_fn("geoip", name),
        max_total_prefixes=budget.max_total_prefixes,
    )
    report.missing_categories |= result.missing
    return result


def _feed_verdicts(
    service: Service,
    loaded: geoip_feed.GeoipResult,
    addresses: Set[str],
) -> List[FeedVerdict]:
    """Заявка каждой категории на место в бюджете.

    Цена — число CIDR в категории, польза — сколько наших адресов она
    подтверждает. Категорию, которая не анонсируется, бюджет не считает, но
    она всё равно попадает в отчёт: без неё непонятно, откуда подтверждение.
    """
    if service.geoip is None:
        return []

    mode = service.geoip.mode
    verdicts = []
    for category in sorted(loaded.by_category):
        prefixes = loaded.by_category[category]
        verdicts.append(FeedVerdict(
            category=category,
            mode=mode,
            prefix_count=len(prefixes),
            corroborated_ips=geoip_feed.count_covered(addresses, prefixes),
        ))
    return verdicts


def _discover_addresses(
    service: Service,
    state: State,
    report: ServiceReport,
    resolve_fn: Callable,
    lookup_fn: Callable,
    extra_targets: Sequence[str] = (),
) -> Dict[str, AsnRecord]:
    """Резолвит цели сервиса и выясняет владельцев адресов."""
    if service.strategy == "asn":
        # v1-режим: доменов нет, разворачиваем то, что указано руками.
        return {}

    targets = resolve.build_targets(
        domains=list(service.domains) + list(extra_targets),
        wildcards=service.wildcards,
        known_hostnames=state.hostnames(service.name),
    )
    if not targets:
        return {}

    result = resolve_fn(targets, service.resolve)
    report.resolve_failed = dict(result.failed)

    state.observe(
        service.name,
        hostnames=[h for h, addrs in result.by_hostname.items() if addrs],
        addresses=result.addresses,
    )

    # State — это память о CDN-адресах до TTL, а не только источник имён.
    # Повторный Cymru lookup сохраняет covering prefix при смене DNS-ответа.
    report.addresses = set(state.addresses(service.name))
    if not report.addresses:
        return {}
    return lookup_fn(sorted(report.addresses))


def _group_by_asn(service: Service, records: Dict[str, AsnRecord]) -> Dict[int, Set[str]]:
    """Собирает «какие адреса привели к какой ASN».

    Ручные ASN попадают сюда всегда, даже если ни один адрес на них не
    указал: оператор перечислил их именно затем, чтобы они были.
    """
    observed: Dict[int, Set[str]] = {asn: set() for asn in service.as_numbers}
    for record in records.values():
        if record.asn is None:
            continue
        observed.setdefault(record.asn, set()).add(record.ip)
    return observed


def _measure_asns(
    observed: Dict[int, Set[str]],
    report: ServiceReport,
    fetch_fn: Callable,
):
    """Узнаёт цену каждой ASN в маршрутах.

    Цена считается после схлопывания — иначе AS15169 со своими 3508
    route-объектами выглядит как дорогая, хотя стоит 83 маршрута.

    Недоступная в IRR ASN не роняет прогон: её адреса всё равно будут
    покрыты блоками от Cymru, просто без разворачивания.
    """
    prefixes: Dict[int, List[Network]] = {}
    costs: Dict[int, float] = {}

    for asn in sorted(observed):
        try:
            fetched = fetch_fn(asn)
        except FetchError as exc:
            report.unreachable_asns[asn] = str(exc)
            logger.warning("AS{}: no IRR data ({}) — covering prefixes only", asn, exc)
            continue
        prefixes[asn] = summarize(fetched)
        costs[asn] = prefix_count(fetched)

    return prefixes, costs


def _apply_strategy(service: Service, verdicts: Sequence[AsnVerdict]) -> List[AsnVerdict]:
    """Учитывает стратегию сервиса поверх решения по размеру ASN."""
    if service.strategy != "covering_prefix":
        return list(verdicts)

    from dataclasses import replace

    return [
        v if v.tier == "rejected"
        else replace(v, tier="limited", reason="strategy=covering_prefix")
        for v in verdicts
    ]


def _collect_prefixes(
    verdicts: Sequence[AsnVerdict],
    records: Dict[str, AsnRecord],
    irr_prefixes: Dict[int, List[Network]],
) -> List[Network]:
    """Превращает решения по ASN в конкретный набор префиксов."""
    collected: List[Network] = []

    for verdict in verdicts:
        if verdict.tier == "rejected":
            continue

        if verdict.tier == "trusted" and verdict.asn in irr_prefixes:
            collected.extend(irr_prefixes[verdict.asn])
            continue

        # limited (или trusted без данных IRR): только блоки вокруг адресов,
        # которые мы действительно видели.
        pool = irr_prefixes.get(verdict.asn, [])
        for ip in sorted(verdict.seen_ips):
            covering = _covering_for(ip, records, pool)
            if covering is not None:
                collected.append(covering)

    return collected


def _covering_for(
    ip: str,
    records: Dict[str, AsnRecord],
    pool: Sequence[Network],
) -> Optional[Network]:
    """Блок, накрывающий адрес: сначала от Cymru, потом из IRR.

    Cymru отдаёт ровно тот префикс, которым адрес анонсируется в BGP, — это
    самый точный ответ. Поиск по IRR остаётся запасным вариантом.
    """
    record = records.get(ip)
    if record is not None and record.prefix is not None:
        return record.prefix
    if pool:
        return irr.covering_prefix(ip, pool)
    return None
