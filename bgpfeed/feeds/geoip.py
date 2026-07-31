"""Разбор geoip-списков и подтверждение ASN по ним.

Списки играют две роли сразу.

**Прямой анонс.** CIDR идут в итоговый набор наравне с префиксами из RADB и
проходят те же guard-ы и тот же бюджет. Список из чужого репозитория не
получает поблажек.

**Подтверждение ASN.** Резолв десятка доменов притаскивает и посторонние
ASN — аналитику, шрифты, сторонние CDN. Единственный фильтр до сих пор был
один: размер ASN. Попадание хотя бы одного резолвнутого адреса в
geoip-категорию сервиса даёт второй, независимый признак.

Подтверждение **никого не выбрасывает** — оно только расширяет порог
доверия. Это соответствует «ложноположительные маршруты лучше их
отсутствия»: неподтверждённая ASN судится по обычному правилу, а не
отвергается.

Чего geoip не умеет: провайдерский GGC-кэш внутри AS аплинка в `geoip:google`
не попадёт никогда — это адреса провайдера. Ради них существует резолв с
vantage point. Списки дополняют конвейер, а не заменяют его.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Set

from loguru import logger

from ..summarize import Network

Loader = Callable[[str], str]


@dataclass
class GeoipResult:
    """Префиксы категорий и то, что при разборе пошло не так."""

    prefixes: List[Network] = field(default_factory=list)
    by_category: Dict[str, List[Network]] = field(default_factory=dict)
    missing: Set[str] = field(default_factory=set)
    oversized: Set[str] = field(default_factory=set)
    skipped: int = 0


def parse(text: str) -> List[Network]:
    """Разбирает список CIDR, пропуская всё, что не разбирается.

    Битая строка не должна стоить нам всего списка: у оборванной закачки
    последняя строка выглядит как `136.50.167.0/` — ровно такой обрубок
    встретился при подготовке задачи.
    """
    prefixes: List[Network] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        network = _parse_line(line)
        if network is not None:
            prefixes.append(network)
    return prefixes


def parse_with_errors(text: str):
    """То же, что `parse`, но ещё и считает непонятые строки."""
    prefixes: List[Network] = []
    skipped = 0
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        network = _parse_line(line)
        if network is None:
            skipped += 1
        else:
            prefixes.append(network)
    return prefixes, skipped


def load_categories(
    categories: Iterable[str],
    loader: Loader,
    max_total_prefixes: Optional[int] = None,
) -> GeoipResult:
    """Загружает и разбирает несколько категорий.

    Категория крупнее всего бюджета (`geoip:ru` — это десятки тысяч
    префиксов) почти наверняка означает опечатку в конфиге, поэтому такие
    отмечаются отдельно и о них говорится громко.
    """
    result = GeoipResult()

    for category in categories:
        try:
            text = loader(category)
        except Exception as exc:  # KeyError от словаря, FetchError от сети
            logger.warning("geoip: category {} unavailable: {}", category, exc)
            result.missing.add(category)
            continue

        prefixes, skipped = parse_with_errors(text)
        result.by_category[category] = prefixes
        result.prefixes.extend(prefixes)
        result.skipped += skipped

        if max_total_prefixes is not None and len(prefixes) > max_total_prefixes:
            result.oversized.add(category)
            logger.warning(
                "geoip: category {} has {} prefixes, more than the whole budget "
                "({}) — is this a typo in the config?",
                category, len(prefixes), max_total_prefixes,
            )
        if skipped:
            logger.warning("geoip: {} — {} unparsable line(s) skipped", category, skipped)

    logger.info("geoip: {} prefix(es) from {} category(ies)",
                len(result.prefixes), len(result.by_category))
    return result


def corroborated_asns(
    observed: Mapping[int, Set[str]],
    prefixes: Iterable[Network],
) -> Set[int]:
    """ASN, у которых хотя бы один резолвнутый адрес лежит в списке.

    Одного попадания достаточно: цель — отличить своих от случайных
    попутчиков, а не доказать принадлежность каждого адреса.
    """
    pool = list(prefixes)
    if not pool:
        return set()

    # Разделение по версиям экономит половину проверок и заодно избавляет от
    # сравнения v4 с v6, на котором ipaddress бросает TypeError.
    by_version: Dict[int, List[Network]] = {4: [], 6: []}
    for network in pool:
        by_version[network.version].append(network)

    corroborated: Set[int] = set()
    for asn, addresses in observed.items():
        if any(_is_covered(address, by_version) for address in addresses):
            corroborated.add(asn)

    if corroborated:
        logger.info("geoip: corroborated ASN(s): {}",
                    ", ".join(f"AS{a}" for a in sorted(corroborated)))
    return corroborated


def count_covered(addresses: Iterable[str], prefixes: Iterable[Network]) -> int:
    """Сколько из наших адресов накрыто списком.

    Это польза категории в лестнице бюджета: категория на 7735 маршрутов
    ради одного адреса должна уступить раньше, чем на 500 ради полусотни.
    """
    by_version: Dict[int, List[Network]] = {4: [], 6: []}
    for network in prefixes:
        by_version[network.version].append(network)
    return sum(1 for address in addresses if _is_covered(address, by_version))


def _is_covered(address: str, by_version: Dict[int, List[Network]]) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in by_version[ip.version])


def _parse_line(line: str) -> Optional[Network]:
    entry = line.split()[0]
    try:
        # strict=False: в списках попадается 1.2.3.4/24 вместо 1.2.3.0/24.
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None
