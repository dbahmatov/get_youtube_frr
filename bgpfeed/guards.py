"""Проверки, отделяющие «собрали префиксы» от «отдали их в BGP».

Guards не пытаются улучшить покрытие — они не дают анонсировать заведомо
опасное. Правило проекта «ложноположительные маршруты лучше их отсутствия»
действует до этой границы и не дальше: лишний /24 Google безвреден,
лишний 0.0.0.0/0 уводит весь трафик роутера.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, List, Optional, Sequence, Union

from loguru import logger

from .config import Guards
from .errors import BgpfeedError
from .summarize import Network, sort_key

# Адреса, которых не может быть в межсетевом анонсе: приватные, служебные,
# документационные, мультикаст. Проверка идёт по вхождению, поэтому
# 10.1.2.0/24 отсекается как часть 10.0.0.0/8.
BOGONS: Sequence[Network] = tuple(
    ipaddress.ip_network(c)
    for c in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "64:ff9b::/96",
        "100::/64",
        "2001:db8::/32",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


def is_bogon(network: Network) -> bool:
    """Попадает ли префикс целиком или частично в неанонсируемое пространство."""
    for bogon in BOGONS:
        if network.version != bogon.version:
            continue
        if network.subnet_of(bogon) or bogon.subnet_of(network):
            return True
    return False


def apply_guards(
    networks: Iterable[Network],
    policy: Guards,
    previous: Optional[Iterable[Network]] = None,
) -> List[Network]:
    """Отбрасывает опасные префиксы и проверяет масштаб изменения.

    `previous` — набор из прошлого запуска. Если он задан и новый набор
    схлопнулся сильнее, чем разрешает `max_change_ratio`, поднимается
    исключение: резкая усушка почти всегда означает сбой источника, а не
    то, что сервис действительно уехал с половины своих адресов.
    """
    kept: List[Network] = []
    for network in sorted(set(networks), key=sort_key):
        if policy.drop_bogons and is_bogon(network):
            logger.warning("guard: dropping bogon {}", network)
            continue
        if network.prefixlen < policy.min_prefix_len:
            logger.warning("guard: dropping {} — prefix wider than /{}",
                           network, policy.min_prefix_len)
            continue
        kept.append(network)

    _check_change_ratio(kept, policy, previous)
    return kept


def _check_change_ratio(
    kept: Sequence[Network],
    policy: Guards,
    previous: Optional[Iterable[Network]],
) -> None:
    if policy.max_change_ratio is None or previous is None:
        return

    before = len(set(previous))
    if before == 0:
        return

    shrink = (before - len(kept)) / before
    if shrink > policy.max_change_ratio:
        raise BgpfeedError(
            f"refusing to announce: prefix count dropped from {before} to {len(kept)} "
            f"({shrink:.0%} change, limit {policy.max_change_ratio:.0%}) — "
            "this usually means a source failed, not that the service moved"
        )
