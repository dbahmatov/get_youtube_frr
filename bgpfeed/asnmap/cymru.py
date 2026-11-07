"""IP → ASN через Team Cymru.

Сервис бесплатный, без ключей и без лимитов — но именно поэтому к нему
стоит ходить вежливо: все адреса уходят одним соединением в bulk-режиме,
а не сотней отдельных запросов.

Приятный побочный эффект bulk-ответа: вместе с ASN приходит и покрывающий
BGP-префикс. Для стратегии `covering_prefix` этого достаточно, и выгрузка
всего RADB широкой ASN не требуется вовсе.

Ответ выглядит так (реальный, из фикстуры):

    15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin | ... | GOOGLE ...
    NA      | 1.2.3.4          | NA                  | AU | apnic| ... | NA

`NA` в колонке ASN означает, что адрес никем не анонсируется. Это валидный
ответ, а не сбой разбора.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence

from loguru import logger

from ..errors import FetchError
from ..summarize import Network

CYMRU_HOST = "whois.cymru.com"
CYMRU_PORT = 43
DEFAULT_TIMEOUT_SEC = 30
DEFAULT_BATCH_SIZE = 1000

NOT_AVAILABLE = "NA"


@dataclass(frozen=True)
class AsnRecord:
    """Что Cymru знает об адресе. `asn is None` — адрес не анонсируется."""

    ip: str
    asn: Optional[int] = None
    prefix: Optional[Network] = None
    as_name: str = ""


def parse_bulk_response(text: str) -> Dict[str, AsnRecord]:
    """Разбирает bulk-ответ в отображение адрес → запись.

    Колонки разделены `|`, но не выровнены: на длинных v6-адресах Cymru
    съезжает. Поэтому режем по разделителю и обрезаем пробелы, а не по
    позициям.
    """
    result: Dict[str, AsnRecord] = {}

    for line in text.splitlines():
        if "|" not in line or line.lstrip().startswith("Bulk mode"):
            continue

        parts = [part.strip() for part in line.split("|")]
        if len(parts) < 3:
            continue

        raw_asn, ip, raw_prefix = parts[0], parts[1], parts[2]
        if not _looks_like_ip(ip):
            continue

        result[ip] = AsnRecord(
            ip=ip,
            asn=_parse_asn(raw_asn),
            prefix=_parse_prefix(raw_prefix),
            as_name=parts[6] if len(parts) > 6 else "",
        )

    return result


def lookup(
    addresses: Iterable[str],
    host: str = CYMRU_HOST,
    port: int = CYMRU_PORT,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> Dict[str, AsnRecord]:
    """Возвращает запись по каждому адресу.

    Адреса, о которых Cymru промолчал, всё равно присутствуют в ответе — с
    `asn=None`. Молча терять их нельзя: выше по конвейеру разница между «нет
    в ответе» и «не анонсируется» неразличима, а вести себя надо по-разному.

    Недоступность сервиса поднимает `FetchError`, а не возвращает пустое
    отображение: пустое означало бы «ни один адрес никому не принадлежит».
    """
    addresses = list(dict.fromkeys(addresses))
    if not addresses:
        return {}

    records: Dict[str, AsnRecord] = {}
    for start in range(0, len(addresses), batch_size):
        batch = addresses[start:start + batch_size]
        parsed = parse_bulk_response(_query(batch, host, port, timeout_sec))
        if not parsed:
            raise FetchError(f"cymru returned no records for a batch of {len(batch)}")
        records.update(parsed)

    missing = [ip for ip in addresses if ip not in records]
    for ip in missing:
        records[ip] = AsnRecord(ip=ip)
    if missing:
        logger.warning("cymru: {} address(es) had no answer", len(missing))

    resolved = sum(1 for r in records.values() if r.asn is not None)
    logger.info("cymru: {} address(es) → {} mapped to an ASN", len(addresses), resolved)
    return records


def _query(batch: Sequence[str], host: str, port: int, timeout_sec: int) -> str:
    request = "begin\nverbose\n" + "\n".join(batch) + "\nend\n"

    try:
        sock = socket.create_connection((host, port), timeout=timeout_sec)
    except socket.timeout as exc:
        raise FetchError(f"cymru timeout connecting to {host}:{port}") from exc
    except OSError as exc:
        raise FetchError(f"cymru unreachable at {host}:{port}: {exc}") from exc

    try:
        sock.sendall(request.encode())
        chunks: List[bytes] = []
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
    except socket.timeout as exc:
        raise FetchError(f"cymru timeout reading from {host}") from exc
    except OSError as exc:
        raise FetchError(f"cymru query failed: {exc}") from exc
    finally:
        sock.close()

    return b"".join(chunks).decode("utf-8", errors="replace")


def _parse_asn(raw: str) -> Optional[int]:
    if not raw or raw == NOT_AVAILABLE:
        return None
    # На некоторых префиксах origin — набор ASN («15169 36561»), тогда
    # первого достаточно: мы всё равно проверяем ASN по размеру, а не по имени.
    first = raw.split()[0]
    try:
        return int(first)
    except ValueError:
        return None


def _parse_prefix(raw: str) -> Optional[Network]:
    if not raw or raw == NOT_AVAILABLE:
        return None
    try:
        return ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
