"""Наблюдение за размером полного анонса без урезания покрытия."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple

from loguru import logger

from .config import Budget, GeoipMode
from .select import AsnVerdict


@dataclass(frozen=True)
class FeedVerdict:
    """Режим и измеренная цена одной geoip-категории."""

    category: str
    mode: GeoipMode
    prefix_count: int
    corroborated_ips: int = 0
    reason: str = ""


def _limited_cost(verdict: AsnVerdict) -> int:
    return len(verdict.seen_ips)


def _cost(verdict: AsnVerdict) -> float:
    if verdict.tier == "rejected":
        return 0.0
    if verdict.tier == "limited":
        return float(_limited_cost(verdict))
    return float(verdict.prefix_count)


def total_cost(verdicts: Iterable[AsnVerdict]) -> float:
    return sum(_cost(verdict) for verdict in verdicts)


def _feed_cost(feed: FeedVerdict) -> float:
    return float(feed.prefix_count) if feed.mode == "announce" else 0.0


def total_cost_all(
    verdicts: Iterable[AsnVerdict],
    feeds: Iterable[FeedVerdict] = (),
) -> float:
    return total_cost(verdicts) + sum(_feed_cost(feed) for feed in feeds)


def fit_all(
    verdicts: Sequence[AsnVerdict],
    feeds: Sequence[FeedVerdict],
    budget: Budget,
) -> Tuple[List[AsnVerdict], List[FeedVerdict]]:
    """Возвращает полный набор; превышение бюджета только журналируется."""
    result = list(verdicts)
    feed_result = list(feeds)
    current = total_cost_all(result, feed_result)
    if current > budget.max_total_prefixes:
        logger.warning(
            "budget: {:g} prefixes exceeds observed limit {} — "
            "keeping full coverage",
            current,
            budget.max_total_prefixes,
        )
    return result, feed_result
