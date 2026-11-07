"""Классификация ASN без автоматического урезания покрытия.

Любая принятая ASN разворачивается целиком из IRR после точного схлопывания.
Размер и geoip-подтверждение остаются видимыми в отчёте, но не переводят ASN
в ``limited``. Урезание допустимо только по явному ``strategy=covering_prefix``
либо как неизбежный fallback, когда IRR недоступен.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Literal, Mapping, Set

from loguru import logger

from .config import AsnPolicy

Tier = Literal["trusted", "limited", "rejected"]

# Цена ASN, о которой ничего не известно. Считаем её дорогой: ошибиться в
# сторону узкого покрытия дешевле, чем развернуть неизвестную ASN целиком.
UNKNOWN_COST = float("inf")


@dataclass(frozen=True)
class AsnVerdict:
    """Решение по одной ASN вместе с обоснованием.

    `reason` печатается в `show asns` и должен читаться человеком: это
    единственный способ понять, почему анонс выглядит именно так.
    """

    asn: int
    tier: Tier
    reason: str
    seen_ips: FrozenSet[str]
    prefix_count: float


def classify_asn(
    asn: int,
    seen_ips: Set[str],
    prefix_count: float,
    policy: AsnPolicy,
    corroborated: bool = False,
) -> AsnVerdict:
    """Решает судьбу одной ASN.

    `corroborated` — попал ли хотя бы один её адрес в geoip-категорию
    сервиса. После T20 это только пояснение в отчёте: признак не меняет tier
    и никого не выбрасывает.
    """
    frozen = frozenset(seen_ips)
    explicit = asn in policy.trusted_asns

    def make(tier: Tier, reason: str) -> AsnVerdict:
        return AsnVerdict(asn=asn, tier=tier, reason=reason,
                          seen_ips=frozen, prefix_count=prefix_count)

    # Запрет сильнее доверия: исключение всегда вносят осознанно, а в
    # trusted_asns ASN может попасть автоматически — из ручных as_numbers.
    if asn in policy.exclude_asns:
        return make("rejected", "excluded by config")

    if explicit:
        return make("trusted", "explicitly listed in config")

    # Пустой seen_ips означает ручную или ещё живую историческую ASN из
    # state. min_ips относится только к новым DNS-наблюдениям.
    if frozen and len(frozen) < policy.min_ips:
        return make(
            "rejected",
            f"only {len(frozen)} resolved IP(s), below min_ips={policy.min_ips}",
        )

    cost = "unknown" if prefix_count == UNKNOWN_COST else f"{prefix_count:g}"
    note = ", corroborated by geoip" if corroborated else ""
    return make(
        "trusted",
        f"{cost} prefixes after collapse; full coverage policy{note}",
    )


def classify_all(
    observed: Mapping[int, Set[str]],
    costs: Mapping[int, float],
    policy: AsnPolicy,
    corroborated_asns: Iterable[int] = (),
) -> List[AsnVerdict]:
    """Классифицирует все встреченные ASN.

    `observed` — какие адреса привели к какой ASN, `costs` — цена ASN в
    маршрутах после схлопывания. Порядок результата детерминирован (по
    номеру ASN), чтобы два прогона на одних данных давали один и тот же
    анонс.
    """
    corroborated = set(corroborated_asns)
    verdicts = [
        classify_asn(asn, observed[asn], costs.get(asn, UNKNOWN_COST), policy,
                     corroborated=asn in corroborated)
        for asn in sorted(observed)
    ]

    if verdicts:
        summary: Dict[str, int] = {}
        for v in verdicts:
            summary[v.tier] = summary.get(v.tier, 0) + 1
        logger.info("select: {} ASN(s) — {}", len(verdicts),
                    ", ".join(f"{k}: {n}" for k, n in sorted(summary.items())))
    return verdicts
