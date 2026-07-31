"""Резолв доменов с привязкой к точке выхода трафика.

Смысл модуля — не «узнать адрес сайта», а «узнать, какой адрес получит
именно этот роутер». Для CDN это разные вещи: ответ зависит от того, откуда
пришёл запрос, и провайдерский GGC-кэш виден только изнутри сети
провайдера. Резолв с чужой машины вернёт чужие адреса, и анонс окажется не
про тот трафик, который мы маршрутизируем.

Поэтому используется dnspython с явным `source` — `socket.getaddrinfo`
биндиться к конкретному адресу не умеет.

Второе сквозное правило: частичный сбой не сокращает результат. Модуль
возвращает то, что получил, и отдельно — список того, что не отрезолвилось,
чтобы вызывающий мог отличить «у сервиса нет адресов» от «DNS моргнул».
Смешать эти два случая — значит снять живые маршруты.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Sequence, Set, Tuple

import dns.exception
import dns.resolver
from loguru import logger

from .config import ResolveConfig, Wildcard

# Значение `resolvers`, означающее «оставить резолвер системы».
SYSTEM_RESOLVER = "system"


@dataclass
class ResolveResult:
    """Что удалось узнать за прогон и что не удалось."""

    by_hostname: Dict[str, Set[str]] = field(default_factory=dict)
    failed: Dict[str, str] = field(default_factory=dict)

    @property
    def addresses(self) -> Set[str]:
        result: Set[str] = set()
        for addresses in self.by_hostname.values():
            result |= addresses
        return result

    @property
    def all_failed(self) -> bool:
        """Ни одного ответа при непустом списке целей.

        Отдельный флаг, а не проверка на пустоту: пустой результат из-за
        сбоя и пустой результат из-за отсутствия целей требуют разной
        реакции выше по конвейеру.
        """
        return bool(self.failed) and not self.addresses


def build_targets(
    domains: Iterable[str],
    wildcards: Iterable[Wildcard],
    known_hostnames: Iterable[str],
) -> List[str]:
    """Собирает список имён для резолва.

    Сам шаблон `*.googlevideo.com` в цели не попадает: его нельзя
    отрезолвить. Вместо него идут `samples` из конфига и всё, что успело
    накопиться в состоянии за прошлые прогоны, — именно накопление и
    покрывает сервис, у которого нет конечного списка имён.
    """
    targets: List[str] = []
    seen = set()
    for source in (domains, (s for w in wildcards for s in w.samples), known_hostnames):
        for name in source:
            if name and name not in seen:
                seen.add(name)
                targets.append(name)
    return targets


def resolve_hostnames(
    hostnames: Sequence[str],
    config: ResolveConfig,
) -> ResolveResult:
    """Резолвит имена, накапливая ответы за несколько раундов.

    Раунды нужны потому, что CDN балансирует ответами: один и тот же запрос
    в разные моменты вернёт разные узлы, и каждый из них — отдельный адрес,
    который стоит покрыть.
    """
    result = ResolveResult()
    hostnames = list(hostnames)
    if not hostnames:
        return result

    for round_number in range(1, max(1, config.rounds) + 1):
        if round_number > 1 and config.round_delay_sec:
            time.sleep(config.round_delay_sec)
        _resolve_round(hostnames, config, result)
        logger.debug("resolve: round {}/{} — {} addresses so far",
                     round_number, config.rounds, len(result.addresses))

    if result.failed:
        logger.warning("resolve: {} of {} hostname(s) failed — announcing what we got, "
                       "not shrinking the result", len(result.failed), len(hostnames))
    logger.info("resolve: {} hostname(s) → {} address(es)",
                len(hostnames), len(result.addresses))
    return result


def _resolve_round(
    hostnames: Sequence[str],
    config: ResolveConfig,
    result: ResolveResult,
) -> None:
    workers = max(1, min(config.concurrency, len(hostnames)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for hostname, addresses, error in pool.map(
            lambda name: _resolve_one(name, config), hostnames
        ):
            if addresses:
                result.by_hostname.setdefault(hostname, set()).update(addresses)
                # Имя, ответившее хотя бы раз, сбоем не считается: в прошлом
                # раунде оно могло отвалиться по таймауту.
                result.failed.pop(hostname, None)
            elif error and hostname not in result.by_hostname:
                result.failed[hostname] = error


def _resolve_one(hostname: str, config: ResolveConfig) -> Tuple[str, Set[str], str]:
    resolver = _build_resolver(config)
    source = config.vantage.source_ip
    addresses: Set[str] = set()
    error = ""

    for record_type in config.record_types:
        try:
            answer = resolver.resolve(hostname, record_type, source=source)
            addresses.update(str(rdata) for rdata in answer)
        except dns.resolver.NoAnswer:
            # Нет AAAA у хоста без v6 — это норма, а не сбой.
            continue
        except (dns.exception.DNSException, OSError) as exc:
            error = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__

    return hostname, addresses, "" if addresses else (error or "no answer")


def _build_resolver(config: ResolveConfig) -> "dns.resolver.Resolver":
    resolver = dns.resolver.Resolver()
    explicit = [r for r in config.vantage.resolvers if r != SYSTEM_RESOLVER]
    if explicit:
        resolver.nameservers = explicit
    resolver.timeout = config.timeout_sec
    resolver.lifetime = config.timeout_sec
    return resolver
