"""Тесты персистентного состояния.

Состояние — это память между прогонами. Она нужна ровно потому, что
`*.googlevideo.com` неперечислим: за один прогон видно несколько хостов, за
месяц — сотни. Накопление и есть механизм покрытия.

Отсюда два требования, которые здесь и стерегутся: накопленное не теряется
при сбое записи, и накопленное не живёт вечно — иначе через год мы будем
анонсировать адреса, которых у сервиса давно нет.
"""

import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from bgpfeed.config import StatePolicy
from bgpfeed.state import State, load_state, save_state

DAY = 86400


@pytest.fixture
def path(tmp_path):
    return str(tmp_path / "state.json")


# --- загрузка ---

def test_missing_file_gives_empty_state(path):
    """Первый запуск — это не ошибка."""
    state = load_state(path)
    assert state.hostnames("youtube") == ()
    assert state.addresses("youtube") == ()


def test_roundtrip(path):
    state = State()
    state.observe("youtube", hostnames=["a.googlevideo.com"], addresses=["8.8.8.8"])
    save_state(state, path)

    loaded = load_state(path)
    assert loaded.hostnames("youtube") == ("a.googlevideo.com",)
    assert loaded.addresses("youtube") == ("8.8.8.8",)


def test_corrupt_file_does_not_lose_previous(path):
    """Битый JSON — повод начать с пустого состояния, а не упасть навсегда."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("{not json")
    state = load_state(path)
    assert state.hostnames("youtube") == ()


def test_unknown_service_is_empty(path):
    state = State()
    state.observe("youtube", hostnames=["a.googlevideo.com"])
    save_state(state, path)
    assert load_state(path).hostnames("jetbrains") == ()


# --- накопление ---

def test_observations_accumulate_across_runs(path):
    """Второй прогон видит другие хосты CDN — оба должны остаться."""
    first = State()
    first.observe("youtube", hostnames=["rr1.googlevideo.com"])
    save_state(first, path)

    second = load_state(path)
    second.observe("youtube", hostnames=["rr2.googlevideo.com"])
    save_state(second, path)

    assert set(load_state(path).hostnames("youtube")) == {
        "rr1.googlevideo.com", "rr2.googlevideo.com",
    }


def test_repeated_observation_is_not_duplicated(path):
    state = State()
    state.observe("youtube", hostnames=["a.googlevideo.com"])
    state.observe("youtube", hostnames=["a.googlevideo.com"])
    assert state.hostnames("youtube") == ("a.googlevideo.com",)


def test_services_are_isolated():
    state = State()
    state.observe("youtube", addresses=["8.8.8.8"])
    state.observe("jetbrains", addresses=["1.1.1.1"])
    assert state.addresses("youtube") == ("8.8.8.8",)
    assert state.addresses("jetbrains") == ("1.1.1.1",)


def test_asns_recorded_with_source():
    state = State()
    state.observe("youtube", asns=[15169])
    assert 15169 in state.asns("youtube")


# --- протухание ---

def test_stale_hostname_expires():
    state = State()
    state.observe("youtube", hostnames=["old.googlevideo.com"], now=time.time() - 100 * DAY)
    state.observe("youtube", hostnames=["new.googlevideo.com"])
    state.expire(StatePolicy(ttl_days=90))
    assert state.hostnames("youtube") == ("new.googlevideo.com",)


def test_fresh_entry_survives_expiry():
    state = State()
    state.observe("youtube", hostnames=["a.googlevideo.com"], now=time.time() - 10 * DAY)
    state.expire(StatePolicy(ttl_days=90))
    assert state.hostnames("youtube") == ("a.googlevideo.com",)


def test_reobserving_refreshes_ttl():
    """Хост, который видели снова, не считается протухшим."""
    state = State()
    old = time.time() - 100 * DAY
    state.observe("youtube", hostnames=["a.googlevideo.com"], now=old)
    state.observe("youtube", hostnames=["a.googlevideo.com"])
    state.expire(StatePolicy(ttl_days=90))
    assert state.hostnames("youtube") == ("a.googlevideo.com",)


def test_manual_asns_never_expire():
    """`keep_manual_forever`: воля оператора не протухает по таймеру."""
    state = State()
    state.observe("youtube", asns=[36561], manual=True, now=time.time() - 1000 * DAY)
    state.expire(StatePolicy(ttl_days=90, keep_manual_forever=True))
    assert 36561 in state.asns("youtube")


def test_manual_asns_expire_when_policy_disabled():
    state = State()
    state.observe("youtube", asns=[36561], manual=True, now=time.time() - 1000 * DAY)
    state.expire(StatePolicy(ttl_days=90, keep_manual_forever=False))
    assert 36561 not in state.asns("youtube")


def test_expiry_is_persisted(path):
    state = State()
    state.observe("youtube", hostnames=["old.host"], now=time.time() - 100 * DAY)
    state.expire(StatePolicy(ttl_days=90))
    save_state(state, path)
    assert load_state(path).hostnames("youtube") == ()


# --- атомарность записи ---

def test_write_is_atomic(path, monkeypatch):
    """Падение в момент записи не должно оставить обрезанный файл."""
    good = State()
    good.observe("youtube", hostnames=["a.googlevideo.com"])
    save_state(good, path)

    broken = State()
    broken.observe("youtube", hostnames=["b.googlevideo.com"])

    real_replace = os.replace

    def fail_replace(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError):
        save_state(broken, path)
    monkeypatch.setattr(os, "replace", real_replace)

    assert load_state(path).hostnames("youtube") == ("a.googlevideo.com",)


def test_no_temp_files_left_behind(path):
    state = State()
    state.observe("youtube", hostnames=["a.googlevideo.com"])
    save_state(state, path)
    leftovers = [n for n in os.listdir(os.path.dirname(path)) if n != os.path.basename(path)]
    assert leftovers == []


def test_creates_parent_directory(tmp_path):
    nested = str(tmp_path / "state" / "sub" / "bgpfeed.json")
    save_state(State(), nested)
    assert os.path.exists(nested)


def test_saved_file_is_readable_json(path):
    state = State()
    state.observe("youtube", hostnames=["a.googlevideo.com"], addresses=["8.8.8.8"])
    save_state(state, path)
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    assert "youtube" in data["services"]


# --- ref фидов ---

def test_feed_ref_recorded(path):
    state = State()
    state.set_feed_ref("geosite", "202607.01")
    save_state(state, path)
    assert load_state(path).feed_ref("geosite") == "202607.01"


def test_unknown_feed_ref_is_none():
    assert State().feed_ref("geosite") is None
