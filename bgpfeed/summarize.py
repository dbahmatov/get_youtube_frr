"""Агрегация префиксов.

Ровно одна операция и никаких вариаций: `ipaddress.collapse_addresses`.
Она склеивает соседние блоки и поглощает вложенные, но никогда не расширяет
покрытие. Три /24 из четырёх остаются /23 плюс /24 — четвёртый, чужой, /24
в анонс не попадает.

Приближённая агрегация («блок заполнен на 80%, округлим до супернета»)
в этом проекте запрещена сознательно: лишний маршрут стоит одной строки
в таблице роутера, а лишний адрес в анонсе — чужого трафика, уведённого
в туннель.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, List, Union

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def sort_key(network: Network):
    """Ключ сортировки, переживающий смесь v4 и v6.

    Штатное сравнение сетей разных семейств кидает TypeError, а смесь у нас
    штатная: RADB отдаёт route и route6 одним ответом.
    """
    return (network.version, int(network.network_address), network.prefixlen)


def summarize(networks: Iterable[Network]) -> List[Network]:
    """Точная агрегация. Результат покрывает ровно те же адреса, что и вход.

    Семейства обрабатываются раздельно (`collapse_addresses` их смешивать
    не умеет) и возвращаются одним отсортированным списком: сначала v4,
    затем v6.
    """
    v4 = []
    v6 = []
    for network in networks:
        (v4 if network.version == 4 else v6).append(network)

    result: List[Network] = []
    if v4:
        result.extend(ipaddress.collapse_addresses(v4))
    if v6:
        result.extend(ipaddress.collapse_addresses(v6))
    return result


def prefix_count(networks: Iterable[Network]) -> int:
    """Цена набора в маршрутах — то есть уже после схлопывания.

    Отдельная функция, потому что считать иначе — конкретная ошибка с
    именем: AS15169 даёт 1831 route-объект и 83 маршрута. Порог
    Для анонса используется второе число; полный схлопнутый набор не
    урезается по размеру.
    """
    return len(summarize(networks))
