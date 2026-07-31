"""Тесты парсера geosite.

Формат проверялся на живом фиде v2fly (ref 20260730073441), фикстуры взяты
оттуда как есть. Что в нём реально встречается:

* голая строка `googlevideo.com` — это суффикс, а не хостнейм;
* `full:www.youtube.com` — конкретный хост;
* атрибуты через пробел: `jetbrains.com.cn @cn`, `2mdn-cn.net @ads`;
* `include:` — в категории `google` их 18, то есть рекурсия обязательна;
* `keyword:`/`regexp:` — не резолвятся, их надо отбрасывать.

Главный риск здесь — зациклиться на взаимных `include:` и подвесить прогон.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from bgpfeed.feeds import geosite

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture(name: str) -> str:
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as handle:
        return handle.read()


def loader_from(mapping):
    """Загрузчик категорий из словаря; отсутствующая — KeyError."""
    def load(category):
        if category not in mapping:
            raise KeyError(category)
        return mapping[category]

    return load


def load(mapping, category="root", **kwargs):
    return geosite.load_category(category, loader_from(mapping), **kwargs)


# --- разбор строк ---

def test_bare_line_is_a_suffix():
    result = load({"root": "googlevideo.com\n"})
    assert result.suffixes == {"googlevideo.com"}
    assert result.hostnames == set()


def test_domain_prefix_is_a_suffix():
    assert load({"root": "domain:googlevideo.com\n"}).suffixes == {"googlevideo.com"}


def test_full_prefix_is_a_hostname():
    result = load({"root": "full:www.youtube.com\n"})
    assert result.hostnames == {"www.youtube.com"}
    assert result.suffixes == set()


def test_keyword_entries_are_skipped():
    """`keyword:youtube` не резолвится — брать его некуда."""
    assert load({"root": "keyword:youtube\n"}).suffixes == set()


def test_regexp_entries_are_skipped():
    assert load({"root": r"regexp:.*\.ytimg\..*" + "\n"}).suffixes == set()


def test_skipped_entries_are_counted():
    """Сколько записей выброшено — видно, а не теряется молча."""
    result = load({"root": "keyword:a\nregexp:b\nyoutube.com\n"})
    assert result.skipped == 2


def test_comments_and_blank_lines_ignored():
    text = "# All .youtube domains\n\n   \nyoutube.com\n"
    assert load({"root": text}).suffixes == {"youtube.com"}


def test_inline_comment_is_stripped():
    assert load({"root": "youtube.com # основной домен\n"}).suffixes == {"youtube.com"}


def test_attributes_are_stripped():
    """`jetbrains.com.cn @cn` — домен с пометкой, а не домен с пробелом."""
    result = load({"root": "jetbrains.com.cn @cn\n2mdn-cn.net @ads\n"})
    assert result.suffixes == {"jetbrains.com.cn", "2mdn-cn.net"}


def test_multiple_attributes_stripped():
    assert load({"root": "example.com @cn @ads\n"}).suffixes == {"example.com"}


def test_case_is_normalised():
    assert load({"root": "YouTube.COM\n"}).suffixes == {"youtube.com"}


def test_duplicates_collapse():
    result = load({"root": "youtube.com\ndomain:youtube.com\nyoutube.com @cn\n"})
    assert result.suffixes == {"youtube.com"}


def test_trailing_dot_normalised():
    assert load({"root": "youtube.com.\n"}).suffixes == {"youtube.com"}


# --- include ---

def test_include_pulls_in_another_category():
    result = load({"root": "include:child\n", "child": "googlevideo.com\n"})
    assert result.suffixes == {"googlevideo.com"}


def test_include_is_recursive():
    result = load({
        "root": "include:a\n",
        "a": "include:b\n",
        "b": "deep.example.com\n",
    })
    assert result.suffixes == {"deep.example.com"}


def test_direct_cycle_does_not_hang():
    """A→B→A. Парсер обязан остановиться, а не крутиться вечно."""
    result = load({"root": "include:a\nroot.example\n",
                   "a": "include:root\na.example\n"})
    assert result.suffixes == {"root.example", "a.example"}


def test_self_include_does_not_hang():
    result = load({"root": "include:root\nself.example\n"})
    assert result.suffixes == {"self.example"}


def test_diamond_include_visits_once():
    """Ромб A→B,C→D: D разбирается один раз, а не дважды."""
    seen = []

    def load_counting(category):
        seen.append(category)
        return {
            "root": "include:b\ninclude:c\n",
            "b": "include:d\n",
            "c": "include:d\n",
            "d": "d.example\n",
        }[category]

    result = geosite.load_category("root", load_counting)
    assert result.suffixes == {"d.example"}
    assert seen.count("d") == 1


def test_missing_included_category_is_survivable():
    """Фид переехал, подкатегории нет — берём что есть, а не падаем."""
    result = load({"root": "include:gone\nyoutube.com\n"})
    assert result.suffixes == {"youtube.com"}
    assert "gone" in result.missing


def test_missing_root_category_is_reported():
    result = load({}, category="nosuch")
    assert result.missing == {"nosuch"}
    assert result.suffixes == set()


# --- исключения ---

def test_exclude_domains_removed():
    result = load({"root": "youtube.com\nggpht.cn\n"}, exclude_domains=("ggpht.cn",))
    assert result.suffixes == {"youtube.com"}


def test_exclude_applies_to_hostnames_too():
    result = load({"root": "full:www.youtube.com\n"},
                  exclude_domains=("www.youtube.com",))
    assert result.hostnames == set()


def test_exclude_is_case_insensitive():
    result = load({"root": "YouTube.com\n"}, exclude_domains=("youtube.COM",))
    assert result.suffixes == set()


def test_exclude_reaches_into_included_categories():
    result = load({"root": "include:child\n", "child": "bad.example\ngood.example\n"},
                  exclude_domains=("bad.example",))
    assert result.suffixes == {"good.example"}


# --- реальные фикстуры ---

def test_real_youtube_category():
    result = geosite.load_category("youtube", lambda c: fixture("geosite_youtube.txt"))
    assert "googlevideo.com" in result.suffixes
    assert "youtu.be" in result.suffixes
    assert "youtube-nocookie.com" in result.suffixes


def test_real_youtube_has_no_includes():
    """Категория плоская — в отличие от `google`. Это разные режимы работы."""
    result = geosite.load_category("youtube", lambda c: fixture("geosite_youtube.txt"))
    assert result.categories == {"youtube"}


def test_real_google_category_is_recursive():
    """18 `include:` в живом фиде — ради этого случая рекурсия и написана."""
    text = fixture("geosite_google.txt")
    result = geosite.load_category("google", lambda c: text if c == "google" else "")
    assert len(result.missing) == 0
    assert len(result.categories) > 1


def test_real_jetbrains_category():
    """Нишевый сервис в фиде тоже есть — вести домены руками не придётся."""
    result = geosite.load_category("jetbrains", lambda c: fixture("geosite_jetbrains.txt"))
    assert "jetbrains.com" in result.suffixes
    assert "kotlinlang.org" in result.suffixes


def test_real_fixture_yields_no_junk():
    """Ни одна взятая запись не должна содержать пробелов и служебных знаков."""
    result = geosite.load_category("youtube", lambda c: fixture("geosite_youtube.txt"))
    for name in result.suffixes | result.hostnames:
        assert " " not in name and "@" not in name and ":" not in name


def test_real_youtube_entry_count_is_sane():
    """178 непустых строк в фиде — после разбора записей должно быть столько же."""
    result = geosite.load_category("youtube", lambda c: fixture("geosite_youtube.txt"))
    assert len(result.suffixes) + len(result.hostnames) + result.skipped == 178
