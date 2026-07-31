"""Память между прогонами.

Зачем она вообще нужна: `*.googlevideo.com` не перечисляется. Хостнеймы
генерируются под конкретного клиента и меняются от запроса к запросу, так
что за один прогон видно горстку, а за месяц — сотни. Накопление
наблюдений и есть способ покрыть сервис, у которого нет конечного списка
имён.

Отсюда двойственность: накопленное нельзя терять при сбое (поэтому запись
атомарна и битый файл не рушит прогон) и нельзя хранить вечно (поэтому
TTL). Исключение — то, что оператор задал руками: его воля не протухает.

Формат файла — плоский JSON, `{сущность: {значение: время последней
встречи}}`. Он должен читаться глазами: это первое, куда смотрят, когда
анонс выглядит неожиданно.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Dict, Iterable, Optional, Tuple

from loguru import logger

from .config import StatePolicy

SCHEMA_VERSION = 1

# Внутри одного сервиса наблюдения разложены по видам: хостнеймы, адреса,
# ASN. Ключ — само значение, значение — момент последней встречи.
_KINDS = ("hostnames", "addresses", "asns")


class State:
    """Наблюдения по сервисам плюс ref загруженных фидов."""

    def __init__(self, services: Optional[Dict] = None, feeds: Optional[Dict] = None):
        self._services: Dict[str, Dict[str, Dict[str, float]]] = services or {}
        self._feeds: Dict[str, str] = feeds or {}
        # ASN, заданные оператором руками. Хранятся отдельно от времени
        # встречи, потому что к ним TTL неприменим по смыслу.
        self._manual: Dict[str, set] = {}

    # --- запись ---

    def observe(
        self,
        service: str,
        hostnames: Iterable[str] = (),
        addresses: Iterable[str] = (),
        asns: Iterable[int] = (),
        manual: bool = False,
        now: Optional[float] = None,
    ) -> None:
        """Отмечает, что эти сущности видели сейчас.

        Повторная встреча обновляет время: живой хост не должен протухать
        только из-за того, что его впервые увидели давно.
        """
        stamp = time.time() if now is None else now
        bucket = self._services.setdefault(service, {kind: {} for kind in _KINDS})

        for name in hostnames:
            bucket.setdefault("hostnames", {})[str(name)] = stamp
        for address in addresses:
            bucket.setdefault("addresses", {})[str(address)] = stamp
        for asn in asns:
            bucket.setdefault("asns", {})[str(asn)] = stamp
            if manual:
                self._manual.setdefault(service, set()).add(str(asn))

    def set_feed_ref(self, feed: str, ref: str) -> None:
        self._feeds[feed] = ref

    # --- чтение ---

    def hostnames(self, service: str) -> Tuple[str, ...]:
        return tuple(sorted(self._bucket(service, "hostnames")))

    def addresses(self, service: str) -> Tuple[str, ...]:
        return tuple(sorted(self._bucket(service, "addresses")))

    def asns(self, service: str) -> Tuple[int, ...]:
        return tuple(sorted(int(a) for a in self._bucket(service, "asns")))

    def feed_ref(self, feed: str) -> Optional[str]:
        return self._feeds.get(feed)

    def age_days(self, service: str, kind: str, value: str) -> Optional[float]:
        """Сколько дней прошло с последней встречи. None, если не встречали."""
        stamp = self._bucket(service, kind).get(str(value))
        return None if stamp is None else (time.time() - stamp) / 86400

    def _bucket(self, service: str, kind: str) -> Dict[str, float]:
        return self._services.get(service, {}).get(kind, {})

    # --- протухание ---

    def expire(self, policy: StatePolicy, now: Optional[float] = None) -> int:
        """Выбрасывает наблюдения старше `ttl_days`. Возвращает число удалённых."""
        stamp = time.time() if now is None else now
        cutoff = stamp - policy.ttl_days * 86400
        removed = 0

        for service, bucket in self._services.items():
            protected = (
                self._manual.get(service, set()) if policy.keep_manual_forever else set()
            )
            for kind, entries in bucket.items():
                stale = [
                    value for value, seen in entries.items()
                    if seen < cutoff and not (kind == "asns" and value in protected)
                ]
                for value in stale:
                    del entries[value]
                removed += len(stale)

        if removed:
            logger.info("state: expired {} observation(s) older than {} days",
                        removed, policy.ttl_days)
        return removed

    # --- сериализация ---

    def to_dict(self) -> Dict:
        return {
            "schema": SCHEMA_VERSION,
            "services": self._services,
            "feeds": self._feeds,
            "manual": {s: sorted(v) for s, v in self._manual.items()},
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "State":
        state = cls(
            services=data.get("services") or {},
            feeds=data.get("feeds") or {},
        )
        state._manual = {s: set(v) for s, v in (data.get("manual") or {}).items()}
        return state


def load_state(path: str) -> State:
    """Читает состояние. Отсутствующий или битый файл даёт пустое состояние.

    Битый файл не должен блокировать анонс навсегда: состояние — это
    ускоритель покрытия, а не его единственный источник. Потеря накопленного
    неприятна, невозможность запуститься — хуже.
    """
    if not os.path.exists(path):
        logger.info("state: {} does not exist yet — starting empty", path)
        return State()

    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("state: {} is unreadable ({}) — starting empty", path, exc)
        return State()

    if not isinstance(data, dict):
        logger.warning("state: {} has unexpected shape — starting empty", path)
        return State()

    return State.from_dict(data)


def save_state(state: State, path: str) -> None:
    """Пишет состояние атомарно: временный файл рядом, затем rename.

    Рядом, а не в /tmp, — иначе rename между файловыми системами не атомарен
    и деградирует до копирования, ради чего всё и затевалось.
    """
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)

    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=directory, prefix=".state-", suffix=".tmp",
        delete=False,
    )
    try:
        with handle:
            json.dump(state.to_dict(), handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        # Прежний файл остаётся нетронутым: он всё ещё лучший источник правды.
        if os.path.exists(handle.name):
            os.unlink(handle.name)
        raise
