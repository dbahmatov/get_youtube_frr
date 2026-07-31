"""Анонс и снятие маршрутов во FRR через vtysh.

Отличия от прежней реализации, каждое из которых стоило бага:

* IPv6 заворачивается в `address-family ipv6 unicast`. Без этого `network`
  с v6-префиксом внутри `router bgp` не применяется — тихо, без ошибки.
* Провалившийся батч поднимает `AnnouncementError`. Раньше он логировался
  и не попадал в счётчик, но запуск завершался как успешный, и половина
  маршрутов оставалась неанонсированной без единого признака в exit-коде.
* Есть reconciliation: CLI читает network нужного `router bgp`, добавляет
  новый импорт и снимает stale-префиксы.
"""

from __future__ import annotations

import ipaddress
import subprocess
import time
from dataclasses import dataclass
from typing import Iterable, List, Sequence

from loguru import logger

from .errors import AnnouncementError
from .summarize import Network, sort_key

DEFAULT_BATCH_SIZE = 1000
DEFAULT_TIMEOUT_SEC = 120


@dataclass(frozen=True)
class ReconciliationPlan:
    """Разница между текущими network FRR и новым импортом."""

    to_add: List[Network]
    to_remove: List[Network]


def parse_configured_networks(text: str, as_number: int) -> List[Network]:
    """Извлекает `network` только из секции указанного `router bgp`."""
    lines = text.splitlines()
    marker = f"router bgp {as_number}"
    try:
        start = next(index for index, line in enumerate(lines) if line.strip() == marker)
    except StopIteration as exc:
        raise AnnouncementError(f"router BGP section for AS{as_number} not found") from exc

    networks = []
    for line in lines[start + 1:]:
        if line and not line.startswith((" ", "!")):
            break
        parts = line.strip().split()
        if len(parts) < 2 or parts[0] != "network":
            continue
        try:
            networks.append(ipaddress.ip_network(parts[1], strict=False))
        except ValueError as exc:
            raise AnnouncementError(
                f"invalid network {parts[1]!r} in running config for AS{as_number}"
            ) from exc
    return sorted(set(networks), key=sort_key)


def get_configured_networks(
    as_number: int,
    timeout_sec: int = 30,
) -> List[Network]:
    """Читает настроенные network из FRR без изменения конфигурации."""
    try:
        completed = subprocess.run(
            ["vtysh", "-c", "show running-config"],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise AnnouncementError(f"cannot read FRR running config: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()[:200]
        raise AnnouncementError(
            f"cannot read FRR running config: vtysh exited with "
            f"{completed.returncode}: {detail}"
        )
    return parse_configured_networks(completed.stdout or "", as_number)


def reconciliation_diff(
    current: Iterable[Network],
    desired: Iterable[Network],
) -> ReconciliationPlan:
    """Строит детерминированный план добавления и удаления network."""
    current_set = set(current)
    desired_set = set(desired)
    return ReconciliationPlan(
        to_add=sorted(desired_set - current_set, key=sort_key),
        to_remove=sorted(current_set - desired_set, key=sort_key),
    )


def build_script(
    as_number: int,
    prefixes: Sequence[Network],
    announce: bool,
) -> str:
    """Собирает текст конфигурации для одного вызова `vtysh -c`."""
    verb = "network" if announce else "no network"
    v4 = [p for p in prefixes if p.version == 4]
    v6 = [p for p in prefixes if p.version == 6]

    lines = ["configure terminal", f"router bgp {as_number}"]
    lines.extend(f"{verb} {p}" for p in v4)
    if v6:
        lines.append("address-family ipv6 unicast")
        lines.extend(f"{verb} {p}" for p in v6)
        lines.append("exit-address-family")
    lines.extend(["exit", "exit"])
    return "\n".join(lines)


def _apply(
    as_number: int,
    prefixes: Iterable[Network],
    announce: bool,
    batch_size: int,
    timeout_sec: int,
    dry_run: bool,
) -> List[str]:
    prefixes = list(prefixes)
    if not prefixes:
        logger.info("frr: nothing to {}", "announce" if announce else "withdraw")
        return []

    batches = [prefixes[i:i + batch_size] for i in range(0, len(prefixes), batch_size)]
    logger.info(
        "frr: {} {} prefixes in {} batch(es)",
        "announcing" if announce else "withdrawing", len(prefixes), len(batches),
    )

    scripts = []
    for number, batch in enumerate(batches, 1):
        # Каждый батч — отдельная сессия vtysh, поэтому `router bgp` открывается
        # заново в каждом скрипте.
        script = build_script(as_number, batch, announce)
        scripts.append(script)
        if dry_run:
            continue
        _run_vtysh(script, number, len(batches), len(batch), timeout_sec)

    return scripts


def _run_vtysh(script: str, number: int, total: int, size: int, timeout_sec: int) -> None:
    started = time.time()
    try:
        completed = subprocess.run(
            ["vtysh", "-c", script],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AnnouncementError(
            f"vtysh timeout after {timeout_sec}s on batch {number}/{total}"
        ) from exc
    except FileNotFoundError as exc:
        raise AnnouncementError(
            "vtysh binary not found — is FRR installed and is this the router host?"
        ) from exc
    except OSError as exc:
        raise AnnouncementError(f"vtysh failed on batch {number}/{total}: {exc}") from exc

    if completed.returncode != 0:
        raise AnnouncementError(
            f"vtysh exited with {completed.returncode} on batch {number}/{total}: "
            f"{(completed.stderr or completed.stdout or '').strip()[:200]}"
        )

    if completed.stderr:
        logger.warning("frr: vtysh stderr: {}", completed.stderr.strip())
    logger.info("frr: batch {}/{} — {} prefixes in {:.2f}s",
                number, total, size, time.time() - started)


def announce(
    as_number: int,
    prefixes: Iterable[Network],
    batch_size: int = DEFAULT_BATCH_SIZE,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    dry_run: bool = False,
) -> List[str]:
    """Анонсирует префиксы. Возвращает поданные во vtysh скрипты."""
    return _apply(as_number, prefixes, True, batch_size, timeout_sec, dry_run)


def withdraw(
    as_number: int,
    prefixes: Iterable[Network],
    batch_size: int = DEFAULT_BATCH_SIZE,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    dry_run: bool = False,
) -> List[str]:
    """Снимает анонс с префиксов."""
    return _apply(as_number, prefixes, False, batch_size, timeout_sec, dry_run)
