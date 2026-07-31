"""Разбор текстовых geosite-списков.

Формат v2fly простой, но с ловушками:

    # комментарий
    googlevideo.com            — суффикс (то же, что domain:googlevideo.com)
    full:www.youtube.com       — конкретный хостнейм
    jetbrains.com.cn @cn       — домен с атрибутом
    include:google-play        — ссылка на другую категорию
    keyword:youtube            — не резолвится, пропускаем
    regexp:.*\\.ytimg\\..*      — не резолвится, пропускаем

Разница между суффиксом и хостнеймом принципиальна: `full:` идёт прямо в
резолв, а суффикс вроде `googlevideo.com` резолвится и сам (у большинства
есть A-запись), и служит основой для накопления хостов вида
`rrN---sn-XXXX.googlevideo.com`, которых в фиде нет и быть не может.

`include:` разворачивается рекурсивно — в живой категории `google` их 18, а
взаимные ссылки между категориями образуют циклы, поэтому обход ведёт
множество посещённых категорий.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from loguru import logger

Loader = Callable[[str], str]

SUFFIX_PREFIX = "domain:"
HOSTNAME_PREFIX = "full:"
INCLUDE_PREFIX = "include:"
SKIPPED_PREFIXES = ("keyword:", "regexp:")


@dataclass
class GeositeResult:
    """Что вытащено из категории и её включений."""

    suffixes: Set[str] = field(default_factory=set)
    hostnames: Set[str] = field(default_factory=set)
    categories: Set[str] = field(default_factory=set)
    missing: Set[str] = field(default_factory=set)
    skipped: int = 0

    @property
    def all_names(self) -> Set[str]:
        return self.suffixes | self.hostnames


@dataclass
class _Parsed:
    suffixes: List[str] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)
    includes: List[str] = field(default_factory=list)
    skipped: int = 0


def parse(text: str) -> _Parsed:
    """Разбирает одну категорию, не трогая её включения."""
    parsed = _Parsed()

    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line:
            continue

        # Атрибуты идут после пробела: `jetbrains.com.cn @cn`.
        entry = line.split()[0]

        if entry.startswith(INCLUDE_PREFIX):
            included = entry[len(INCLUDE_PREFIX):].strip()
            if included:
                parsed.includes.append(included)
            continue

        if entry.startswith(SKIPPED_PREFIXES):
            parsed.skipped += 1
            continue

        if entry.startswith(HOSTNAME_PREFIX):
            name = _normalise(entry[len(HOSTNAME_PREFIX):])
            if name:
                parsed.hostnames.append(name)
            continue

        if entry.startswith(SUFFIX_PREFIX):
            entry = entry[len(SUFFIX_PREFIX):]
        name = _normalise(entry)
        if name:
            parsed.suffixes.append(name)

    return parsed


def load_category(
    category: str,
    loader: Loader,
    exclude_domains: Iterable[str] = (),
    result: Optional[GeositeResult] = None,
) -> GeositeResult:
    """Разворачивает категорию вместе со всеми её `include:`.

    Отсутствующая категория не считается ошибкой: фид живёт своей жизнью,
    подкатегории в нём переименовывают и удаляют. Такое отмечается в
    `missing`, а работа продолжается на том, что нашлось, — пропасть без
    маршрутов хуже, чем пропасть без части доменов.
    """
    result = result if result is not None else GeositeResult()
    excluded = {_normalise(d) for d in exclude_domains}
    _walk(category, loader, result, excluded)

    if result.missing:
        logger.warning("geosite: missing categories: {}", ", ".join(sorted(result.missing)))
    logger.info(
        "geosite: {} — {} suffix(es), {} hostname(s) from {} category(ies), {} skipped",
        category, len(result.suffixes), len(result.hostnames),
        len(result.categories), result.skipped,
    )
    return result


def _walk(category: str, loader: Loader, result: GeositeResult,
          excluded: Set[str]) -> None:
    if category in result.categories or category in result.missing:
        # Уже разобрана. Без этой проверки взаимные include: зациклят обход.
        return

    try:
        text = loader(category)
    except Exception as exc:  # KeyError от словаря, FetchError от сети
        logger.warning("geosite: category {} unavailable: {}", category, exc)
        result.missing.add(category)
        return

    result.categories.add(category)
    parsed = parse(text)
    result.skipped += parsed.skipped
    result.suffixes.update(n for n in parsed.suffixes if n not in excluded)
    result.hostnames.update(n for n in parsed.hostnames if n not in excluded)

    for included in parsed.includes:
        _walk(included, loader, result, excluded)


def _strip_comment(line: str) -> str:
    head = line.split("#", 1)[0]
    return head.strip()


def _normalise(name: str) -> str:
    return name.strip().rstrip(".").lower()
