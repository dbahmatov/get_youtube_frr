"""Тесты загрузки фидов с кэшем и пиннингом.

Список из чужого репозитория попадает прямо в BGP-анонс, поэтому здесь
проверяется не только «скачалось», но и всё, что может пойти не так тихо:

* оборванная закачка выглядит как валидный список — этот случай встретился
  живьём при подготовке задачи: `head` закрыл пайп на 24 KiB, и файл из 7735
  строк превратился в 1511, оканчиваясь обрубком `136.50.167.0/`;
* смена `ref` не должна молча отдавать старый кэш;
* пропажа сети не должна ронять прогон, если кэш есть.
"""

import hashlib
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from bgpfeed.config import FeedSource, FeedsConfig
from bgpfeed.errors import FetchError
from bgpfeed.feeds import fetcher

BODY = "youtube.com\ngooglevideo.com\nytimg.com\n"
SOURCE = FeedSource(
    url="https://example.invalid/{ref}/data/{category}",
    ref="20260730073441",
)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class FakeOpener:
    """Загрузчик-заглушка с настраиваемым поведением."""

    def __init__(self, body=BODY, error=None, content_length=None):
        self.body = body
        self.error = error
        self.content_length = content_length
        self.calls = []

    def __call__(self, url, timeout=None):
        self.calls.append(url)
        if self.error is not None:
            raise self.error
        length = self.content_length
        if length is None:
            length = len(self.body.encode())
        return self.body.encode(), length


@pytest.fixture
def feeds(tmp_path):
    return FeedsConfig(cache_dir=str(tmp_path / "feeds"), refresh_days=7)


def fetch(feeds, opener, source=SOURCE, category="youtube", **kwargs):
    return fetcher.fetch_category(source, category, feeds, opener=opener, **kwargs)


# --- базовая загрузка ---

def test_fetches_and_returns_body(feeds):
    assert fetch(feeds, FakeOpener()) == BODY


def test_ref_and_category_substituted_into_url(feeds):
    opener = FakeOpener()
    fetch(feeds, opener)
    assert opener.calls == [
        "https://example.invalid/20260730073441/data/youtube"
    ]


def test_body_is_cached_on_disk(feeds):
    fetch(feeds, FakeOpener())
    path = fetcher.cache_path(SOURCE, "youtube", feeds)
    assert os.path.exists(path)
    with open(path, encoding="utf-8") as handle:
        assert handle.read() == BODY


def test_cache_directory_is_created(feeds):
    fetch(feeds, FakeOpener())
    assert os.path.isdir(feeds.cache_dir)


# --- кэш и refresh_days ---

def test_fresh_cache_is_reused_without_network(feeds):
    fetch(feeds, FakeOpener())
    second = FakeOpener(body="ЭТОГО НЕ ДОЛЖНО БЫТЬ")
    assert fetch(feeds, second) == BODY
    assert second.calls == []


def test_force_refresh_bypasses_fresh_cache(feeds):
    fetch(feeds, FakeOpener(body="старый список\n"))
    opener = FakeOpener(body="новый список\n")

    result = fetcher.fetch_category(
        SOURCE, "youtube", feeds, opener=opener, force_refresh=True,
    )

    assert result == "новый список\n"
    assert opener.calls


def test_stale_cache_is_refetched(feeds):
    fetch(feeds, FakeOpener())
    path = fetcher.cache_path(SOURCE, "youtube", feeds)
    old = time.time() - 8 * 86400
    os.utime(path, (old, old))

    fresh = FakeOpener(body="обновлённый список\n")
    assert fetch(feeds, fresh) == "обновлённый список\n"
    assert fresh.calls


def test_refresh_days_zero_always_refetches(feeds):
    always = FeedsConfig(cache_dir=feeds.cache_dir, refresh_days=0)
    fetch(always, FakeOpener())
    second = FakeOpener(body="новое\n")
    assert fetch(always, second) == "новое\n"


def test_changing_ref_does_not_reuse_old_cache(feeds):
    """Смена ref — это другой список. Отдать старый кэш значило бы соврать."""
    fetch(feeds, FakeOpener())
    other = FeedSource(url=SOURCE.url, ref="20260731000000")
    opener = FakeOpener(body="список нового релиза\n")
    assert fetcher.fetch_category(other, "youtube", feeds, opener=opener) == \
        "список нового релиза\n"
    assert opener.calls


def test_categories_cached_separately(feeds):
    fetch(feeds, FakeOpener(body="youtube-список\n"), category="youtube")
    assert fetch(feeds, FakeOpener(body="google-список\n"), category="google") == \
        "google-список\n"


# --- работа без сети ---

def test_offline_falls_back_to_stale_cache(feeds):
    """Нет сети, есть кэш — работаем на нём. Анонс важнее свежести."""
    fetch(feeds, FakeOpener())
    path = fetcher.cache_path(SOURCE, "youtube", feeds)
    old = time.time() - 90 * 86400
    os.utime(path, (old, old))

    assert fetch(feeds, FakeOpener(error=OSError("network unreachable"))) == BODY


def test_offline_without_cache_raises(feeds):
    """Ни сети, ни кэша — это сбой источника, а не пустой список."""
    with pytest.raises(FetchError):
        fetch(feeds, FakeOpener(error=OSError("network unreachable")))


def test_offline_not_ok_raises_even_with_cache(feeds):
    strict = FeedsConfig(cache_dir=feeds.cache_dir, refresh_days=0, offline_ok=False)
    fetcher.fetch_category(SOURCE, "youtube", strict, opener=FakeOpener())
    with pytest.raises(FetchError):
        fetcher.fetch_category(SOURCE, "youtube", strict,
                               opener=FakeOpener(error=OSError("down")))


def test_http_error_is_a_fetch_error(feeds):
    with pytest.raises(FetchError):
        fetch(feeds, FakeOpener(error=ValueError("HTTP 404")))


# --- целостность ---

def test_truncated_download_is_rejected(feeds):
    """Обрыв закачки — правдоподобный список, которому нельзя верить.

    Сервер обещал больше байт, чем пришло. Молча принять такое — значит
    анонсировать половину списка и не заметить.
    """
    opener = FakeOpener(body=BODY, content_length=len(BODY.encode()) + 500)
    with pytest.raises(FetchError, match="truncated|incomplete"):
        fetch(feeds, opener)


def test_truncated_download_does_not_poison_cache(feeds):
    """Битая закачка при живом кэше: остаёмся на проверенном списке.

    Падать здесь не за что — прошлый список цел и годен. Но и подменять им
    кэш нельзя: тогда обрубок стал бы новой «истиной».
    """
    fetch(feeds, FakeOpener())
    bad = FeedsConfig(cache_dir=feeds.cache_dir, refresh_days=0)
    opener = FakeOpener(body="обрубок", content_length=9999)

    assert fetcher.fetch_category(SOURCE, "youtube", bad, opener=opener) == BODY
    with open(fetcher.cache_path(SOURCE, "youtube", feeds), encoding="utf-8") as handle:
        assert handle.read() == BODY


def test_truncated_download_without_cache_raises(feeds):
    """Кэша нет — прикрыться нечем, и это честная ошибка источника."""
    opener = FakeOpener(body="обрубок", content_length=9999)
    with pytest.raises(FetchError, match="truncated"):
        fetch(feeds, opener)


def test_sha256_mismatch_keeps_serving_the_cached_copy(feeds):
    """Подменённый фид не должен ни попасть в анонс, ни обрушить прогон."""
    fetch(feeds, FakeOpener())
    pinned = FeedSource(url=SOURCE.url, ref=SOURCE.ref, sha256=sha256(BODY))
    stale = FeedsConfig(cache_dir=feeds.cache_dir, refresh_days=0)

    result = fetcher.fetch_category(
        pinned, "youtube", stale, opener=FakeOpener(body="подменённый список\n")
    )
    assert result == BODY


def test_sha256_mismatch_is_rejected(feeds):
    source = FeedSource(url=SOURCE.url, ref=SOURCE.ref, sha256=sha256("что-то другое"))
    with pytest.raises(FetchError, match="sha256"):
        fetch(feeds, FakeOpener(), source=source)


def test_sha256_match_passes(feeds):
    source = FeedSource(url=SOURCE.url, ref=SOURCE.ref, sha256=sha256(BODY))
    assert fetch(feeds, FakeOpener(), source=source) == BODY


def test_sha256_is_checked_per_category(feeds):
    google = "google.example\n"
    source = FeedSource(
        url=SOURCE.url,
        ref=SOURCE.ref,
        sha256={"youtube": sha256(BODY), "google": sha256(google)},
    )

    assert fetch(feeds, FakeOpener(body=BODY), source=source) == BODY
    with pytest.raises(FetchError, match="sha256"):
        fetch(
            feeds, FakeOpener(body="подмена\n"), source=source, category="google",
        )


def test_fresh_cache_is_verified_before_use(feeds):
    fetch(feeds, FakeOpener())
    source = FeedSource(url=SOURCE.url, ref=SOURCE.ref, sha256=sha256("другое"))

    with pytest.raises(FetchError, match="sha256"):
        fetch(feeds, FakeOpener(body=BODY), source=source)


def test_offline_fallback_cache_is_verified(feeds):
    fetch(feeds, FakeOpener())
    path = fetcher.cache_path(SOURCE, "youtube", feeds)
    old = time.time() - 90 * 86400
    os.utime(path, (old, old))
    source = FeedSource(url=SOURCE.url, ref=SOURCE.ref, sha256=sha256("другое"))

    with pytest.raises(FetchError, match="cache"):
        fetch(feeds, FakeOpener(error=OSError("down")), source=source)


def test_cached_info_does_not_return_tampered_cache(feeds):
    fetch(feeds, FakeOpener())
    source = FeedSource(url=SOURCE.url, ref=SOURCE.ref, sha256=sha256("другое"))

    assert fetcher.cached_category_info(source, "youtube", feeds) is None


def test_sha256_mismatch_does_not_poison_cache(feeds):
    source = FeedSource(url=SOURCE.url, ref=SOURCE.ref, sha256=sha256("другое"))
    with pytest.raises(FetchError):
        fetch(feeds, FakeOpener(), source=source)
    assert not os.path.exists(fetcher.cache_path(source, "youtube", feeds))


def test_missing_sha256_warns_with_the_actual_hash(feeds, caplog):
    """Без sha256 фид не проверяется — подсказываем, что вписать в конфиг."""
    messages = []
    fetch(feeds, FakeOpener(), on_warning=messages.append)
    assert any(sha256(BODY) in m for m in messages)


def test_empty_body_is_rejected(feeds):
    """Пустой ответ — почти наверняка сбой, а не категория без записей."""
    with pytest.raises(FetchError):
        fetch(feeds, FakeOpener(body=""))


# --- атомарность ---

def test_cache_write_leaves_no_temp_files(feeds):
    fetch(feeds, FakeOpener())
    leftovers = [n for n in os.listdir(feeds.cache_dir) if n.startswith("tmp")]
    assert leftovers == []


def test_unreadable_cache_falls_back_to_network(feeds):
    """Битый кэш не должен быть тупиком: перекачиваем."""
    fetch(feeds, FakeOpener())
    path = fetcher.cache_path(SOURCE, "youtube", feeds)
    os.remove(path)
    os.mkdir(path)  # на месте файла теперь каталог — чтение упадёт

    assert fetch(feeds, FakeOpener(body="перекачано\n")) == "перекачано\n"
