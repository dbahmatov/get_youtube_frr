"""Загрузка фидов с кэшем, пиннингом и проверкой целостности.

Правила, из которых собран модуль:

* **Кэш по (ref, категория).** Смена `ref` — это другой список, старый кэш
  для него не подходит. Поэтому ref входит в имя файла.
* **Оборванная закачка отвергается.** Обрубок выглядит как нормальный
  список: последняя строка просто короче. Если сервер сказал, сколько
  байт будет, расхождение — повод отказаться, а не молча анонсировать
  половину.
* **Кэш не портится неудачей.** Проверки идут до записи: битая закачка
  оставляет прошлый, заведомо целый список на месте.
* **Нет сети — не повод падать.** При `offline_ok` протухший кэш лучше
  отсутствия маршрутов.

Загрузчик передаётся параметром: так модуль тестируется без сети.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import time
import urllib.error
import urllib.request
from typing import Callable, Optional, Tuple

from loguru import logger

from ..config import FeedSource, FeedsConfig
from ..errors import FetchError

USER_AGENT = "bgpfeed/2 (+https://github.com/)"
TIMEOUT_SEC = 30
Opener = Callable[[str, Optional[float]], Tuple[bytes, Optional[int]]]


def build_url(source: FeedSource, category: str) -> str:
    """Подставляет ref и категорию в шаблон URL."""
    try:
        return source.url.format(ref=source.ref, category=category)
    except KeyError as exc:
        raise FetchError(
            f"feed url template {source.url!r} uses unknown placeholder {exc}; "
            "only {ref} and {category} are available"
        ) from exc


def cache_path(source: FeedSource, category: str, feeds: FeedsConfig) -> str:
    """Путь кэша для конкретной пары (ref, категория).

    Имя файла содержит хэш URL: категории из разных источников не должны
    сталкиваться, а сам URL в имя файла не превратить.
    """
    digest = hashlib.sha256(build_url(source, category).encode()).hexdigest()[:16]
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in category)
    return os.path.join(feeds.cache_dir, f"{safe}-{source.ref}-{digest}.txt")


def fetch_category(
    source: FeedSource,
    category: str,
    feeds: FeedsConfig,
    opener: Optional[Opener] = None,
    now: Optional[float] = None,
    on_warning: Optional[Callable[[str], None]] = None,
    force_refresh: bool = False,
) -> str:
    """Возвращает содержимое категории фида, скачивая его при необходимости."""
    opener = opener or _download
    now = time.time() if now is None else now
    warn = _warner(on_warning)

    path = cache_path(source, category, feeds)
    expected = _expected_hash(source, category)
    if not force_refresh and _is_fresh(path, feeds.refresh_days, now):
        cached = _read_cache(path, expected)
        if cached is not None:
            logger.debug("feeds: {} — using cache {}", category, path)
            return cached

    url = build_url(source, category)
    try:
        body = _fetch_and_verify(url, source, category, opener, warn)
    except FetchError as exc:
        cached = _read_cache(path, expected) if feeds.offline_ok else None
        if cached is None:
            raise FetchError(f"{exc}; no verified cached copy available") from exc
        warn(f"feeds: {category} — source unavailable, falling back to cached copy")
        return cached

    _write_cache(path, body, warn)
    logger.info("feeds: {} — {} bytes from {}", category, len(body.encode()), url)
    return body


def cached_category_info(
    source: FeedSource,
    category: str,
    feeds: FeedsConfig,
    now: Optional[float] = None,
) -> Optional[Tuple[float, str]]:
    """Возвращает возраст и содержимое кэша, не обращаясь к сети."""
    path = cache_path(source, category, feeds)
    try:
        modified = os.path.getmtime(path)
    except OSError:
        return None
    body = _read_cache(path, _expected_hash(source, category))
    if body is None:
        return None
    current = time.time() if now is None else now
    return max(0.0, current - modified), body


def _expected_hash(source: FeedSource, category: str) -> Optional[str]:
    hashes = source.sha256
    if not hashes:
        return None
    if isinstance(hashes, str):  # прямой вызов со старым скалярным значением
        return hashes
    return hashes.get(category) or hashes.get("*")


def _fetch_and_verify(url: str, source: FeedSource, category: str,
                      opener: Opener, warn: Callable[[str], None]) -> str:
    """Качает ресурс и проверяет, что получен он целиком и тот самый."""
    try:
        raw, expected_length = opener(url, TIMEOUT_SEC)
    except FetchError:
        raise
    except Exception as exc:
        raise FetchError(f"cannot fetch {url}: {exc}") from exc

    if expected_length is not None and len(raw) != expected_length:
        raise FetchError(
            f"truncated download from {url}: got {len(raw)} bytes, "
            f"server announced {expected_length}"
        )
    if not raw.strip():
        raise FetchError(f"empty response from {url} — treating as a source failure")

    digest = hashlib.sha256(raw).hexdigest()
    expected = _expected_hash(source, category)
    if expected:
        if digest != expected:
            raise FetchError(
                f"sha256 mismatch for {url}: expected {expected}, got {digest}"
            )
    else:
        warn(
            f"feeds: {url} is unpinned by hash; add sha256: "
            f"{{ {category}: {digest} }} to the config"
        )

    return raw.decode("utf-8", errors="replace")


def _download(url: str, timeout: Optional[float] = None):
    """Настоящая загрузка. Отдаёт тело и обещанную сервером длину."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
            header = response.headers.get("Content-Length")
    except urllib.error.HTTPError as exc:
        raise FetchError(f"cannot fetch {url}: HTTP {exc.code} {exc.reason}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise FetchError(f"cannot fetch {url}: {exc}") from exc

    expected = None
    if header is not None:
        try:
            expected = int(header)
        except ValueError:
            expected = None
    return body, expected


def _is_fresh(path: str, refresh_days: int, now: float) -> bool:
    if refresh_days <= 0:
        return False
    try:
        age = now - os.path.getmtime(path)
    except OSError:
        return False
    return age < refresh_days * 86400


def _read_cache(path: str, expected: Optional[str] = None) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            body = handle.read()
    except FileNotFoundError:
        # Первая загрузка категории — обычное дело, шуметь не о чем.
        return None
    except OSError as exc:
        logger.warning("feeds: cannot read cache {}: {}", path, exc)
        return None

    if expected and hashlib.sha256(body.encode()).hexdigest() != expected:
        logger.warning("feeds: cached copy {} failed sha256 check", path)
        return None
    return body


def _write_cache(path: str, body: str, warn: Callable[[str], None]) -> None:
    """Пишет кэш атомарно: оборванная запись не должна оставить огрызок."""
    directory = os.path.dirname(path) or "."
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as exc:
        warn(f"feeds: cannot create cache dir {directory}: {exc}")
        return

    handle = None
    try:
        handle = tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=directory, delete=False
        )
        handle.write(body)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        os.replace(handle.name, path)
    except OSError as exc:
        # Кэш — оптимизация, а не результат: не смогли записать, но список у
        # нас на руках и прогон должен продолжиться.
        warn(f"feeds: cannot write cache {path}: {exc}")
        if handle is not None:
            _unlink(handle.name)
    except BaseException:
        if handle is not None:
            handle.close()
            _unlink(handle.name)
        raise


def _unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _warner(on_warning: Optional[Callable[[str], None]]) -> Callable[[str], None]:
    def warn(message: str) -> None:
        logger.warning("{}", message)
        if on_warning is not None:
            on_warning(message)

    return warn
