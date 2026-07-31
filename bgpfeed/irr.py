"""Выгрузка префиксов ASN из IRR (RADB).

Один внешний вызов — `whois -h whois.radb.net -- -i origin ASxxxxx` — и
парсер его ответа. Команда собирается списком аргументов: строковая сборка
с `shell=True`, как было раньше, отдаёт номер ASN на разбор шеллу.

Пустой ответ поднимает `FetchError`, а не возвращает пустой список. Эти два
исхода различаются принципиально: «у ASN нет префиксов» уехало бы дальше по
конвейеру и превратилось в withdraw всего, что было анонсировано.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from typing import Iterable, List, Optional

from loguru import logger

from .errors import FetchError
from .summarize import Network, sort_key

RADB_HOST = "whois.radb.net"
DEFAULT_TIMEOUT_SEC = 120

# Ровно начало строки: `descr:` со случайным префиксом в тексте не должен
# приниматься за route-объект.
ROUTE_RE = re.compile(r"^route6?:\s*(\S+)\s*$", re.MULTILINE)


def parse_route_objects(text: str) -> List[Network]:
    """Достаёт префиксы из вывода whois: route и route6, без дублей.

    RADB отдаёт один и тот же префикс дважды — как объект IRR и как
    результат автоматической конвертации RPKI→IRR. Для нас это один маршрут.
    """
    found = set()
    for raw in ROUTE_RE.findall(text):
        try:
            found.add(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            logger.debug("irr: skipping unparsable prefix {!r}", raw)
    return sorted(found, key=sort_key)


def covering_prefix(address: str, prefixes: Iterable[Network]) -> Optional[Network]:
    """Самый специфичный префикс из набора, покрывающий адрес.

    Основа стратегии `covering_prefix`: для широких ASN вроде AS15169 мы не
    разворачиваем весь их RADB, а берём только те блоки, в которые реально
    попали отрезолвленные адреса. Специфичный, а не первый попавшийся: у
    Google адрес накрывается и /24, и /12 сразу, и /24 стоит одного маршрута
    вместо миллиона чужих адресов.
    """
    ip = ipaddress.ip_address(address)
    best: Optional[Network] = None
    for prefix in prefixes:
        if prefix.version != ip.version or ip not in prefix:
            continue
        if best is None or prefix.prefixlen > best.prefixlen:
            best = prefix
    return best


def fetch_prefixes(
    asn: int,
    host: str = RADB_HOST,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> List[Network]:
    """Возвращает префиксы, объявленные с origin `asn`, по данным IRR."""
    if isinstance(asn, bool) or not isinstance(asn, int):
        raise FetchError(f"invalid AS number {asn!r}: must be an integer")

    query = f"AS{asn}"
    # Запрос идёт одной строкой: клиент whois передаёт аргументы серверу как
    # есть, и разбитый на части `-i origin ASxxx` доезжает до RADB как флаг
    # без аргумента — сервер отвечает «No entries found».
    command = ["whois", "-h", host, "--", f"-i origin {query}"]
    logger.debug("irr: querying {} for {}", host, query)

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise FetchError(f"whois timeout after {timeout_sec}s querying {query}") from exc
    except FileNotFoundError as exc:
        raise FetchError("whois binary not found — install the 'whois' package") from exc
    except OSError as exc:
        raise FetchError(f"whois failed for {query}: {exc}") from exc

    if completed.returncode != 0:
        raise FetchError(
            f"whois exited with {completed.returncode} for {query}: "
            f"{(completed.stderr or '').strip()[:200]}"
        )

    prefixes = parse_route_objects(completed.stdout or "")
    if not prefixes:
        raise FetchError(
            f"no route objects for {query} at {host} — "
            "treating as a source failure, not as an empty ASN"
        )

    logger.info("irr: {} → {} route objects", query, len(prefixes))
    return prefixes
