"""Тесты загрузки и валидации конфига.

Главное, что здесь стережётся, — обратная совместимость с v1. Существующий
config.yaml пользователя обязан грузиться без правок и вести себя ровно так же,
как вёл до появления доменного конвейера.
"""

import os
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from bgpfeed.config import load_config
from bgpfeed.errors import ConfigError

REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


def write_config(tmp_path, text: str) -> str:
    path = tmp_path / "config.yaml"
    path.write_text(textwrap.dedent(text))
    return str(path)


# --- v1: обратная совместимость ---

V1_CONFIG = """
    router:
      as_number: 65001
      services:
        youtube:
          as_numbers:
            - 36561
            - 15169
        jetbrains:
          as_numbers:
            - 200019
      log_file: "logs/routes.log"
"""


def test_v1_config_loads(tmp_path):
    cfg = load_config(write_config(tmp_path, V1_CONFIG))
    assert cfg.as_number == 65001
    assert cfg.log_file == "logs/routes.log"
    assert sorted(s.name for s in cfg.services) == ["jetbrains", "youtube"]


def test_v1_service_keeps_as_numbers(tmp_path):
    cfg = load_config(write_config(tmp_path, V1_CONFIG))
    youtube = cfg.service("youtube")
    assert youtube.as_numbers == (36561, 15169)


def test_v1_service_uses_asn_strategy(tmp_path):
    """v1 не знает про резолв: ASN разворачивается целиком, как раньше."""
    cfg = load_config(write_config(tmp_path, V1_CONFIG))
    assert cfg.service("youtube").strategy == "asn"


def test_v1_service_has_no_discovery_sources(tmp_path):
    cfg = load_config(write_config(tmp_path, V1_CONFIG))
    youtube = cfg.service("youtube")
    assert youtube.domains == ()
    assert youtube.wildcards == ()
    assert youtube.geosite is None
    assert youtube.geoip is None


def test_v1_manual_asns_are_trusted(tmp_path):
    """Явная воля оператора важнее эвристики по размеру ASN."""
    cfg = load_config(write_config(tmp_path, V1_CONFIG))
    policy = cfg.service("youtube").asn_policy
    assert 36561 in policy.trusted_asns
    assert 15169 in policy.trusted_asns


def test_real_repo_config_loads():
    """Реальный config.yaml из репозитория грузится без правок."""
    cfg = load_config(os.path.join(REPO_ROOT, "config.yaml"))
    assert cfg.as_number == 65001
    names = sorted(s.name for s in cfg.services)
    assert names == ["clode.ai", "hashicorp", "jetbrains", "youtube"]
    assert cfg.service("youtube").as_numbers == (36561, 15169, 36040, 43515)


# --- v2 ---

V2_CONFIG = """
    version: 2
    router:
      as_number: 65001
      log_file: logs/routes.log
      state_file: state/bgpfeed.json
    feeds:
      cache_dir: state/feeds
      refresh_days: 7
      geosite:
        url: "https://example.invalid/geosite.txt"
        ref: "202607.01"
      geoip:
        url: "https://example.invalid/geoip.txt"
        ref: "202607.01"
    defaults:
      strategy: hybrid
      asn_selection:
        trusted_max_prefixes: 2000
      budget:
        max_total_prefixes: 20000
    services:
      youtube:
        geosite:
          categories: [youtube, googlevideo]
        geoip:
          categories: [google]
          mode: announce
        domains: [youtubei.googleapis.com]
        wildcards:
          - pattern: "*.googlevideo.com"
            samples: [redirector.googlevideo.com]
        as_numbers: [36561]
      jetbrains:
        domains: [jetbrains.com]
        asn_selection:
          trusted_max_prefixes: 50
"""


def test_v2_loads_sources(tmp_path):
    cfg = load_config(write_config(tmp_path, V2_CONFIG))
    youtube = cfg.service("youtube")
    assert youtube.geosite.categories == ("youtube", "googlevideo")
    assert youtube.geoip.categories == ("google",)
    assert youtube.geoip.mode == "announce"
    assert youtube.domains == ("youtubei.googleapis.com",)


def test_v2_wildcard_samples(tmp_path):
    cfg = load_config(write_config(tmp_path, V2_CONFIG))
    wildcard = cfg.service("youtube").wildcards[0]
    assert wildcard.pattern == "*.googlevideo.com"
    assert wildcard.samples == ("redirector.googlevideo.com",)


def test_defaults_merge_into_services(tmp_path):
    cfg = load_config(write_config(tmp_path, V2_CONFIG))
    assert cfg.service("youtube").asn_policy.trusted_max_prefixes == 2000
    assert cfg.service("youtube").strategy == "hybrid"


def test_service_overrides_defaults(tmp_path):
    """Настройка сервиса перекрывает defaults, не затирая остальные поля."""
    cfg = load_config(write_config(tmp_path, V2_CONFIG))
    jetbrains = cfg.service("jetbrains")
    assert jetbrains.asn_policy.trusted_max_prefixes == 50
    assert jetbrains.asn_policy.min_ips == 1  # дефолт уцелел


def test_v2_manual_asns_still_trusted(tmp_path):
    cfg = load_config(write_config(tmp_path, V2_CONFIG))
    assert 36561 in cfg.service("youtube").asn_policy.trusted_asns


def test_budget_default_applied(tmp_path):
    cfg = load_config(write_config(tmp_path, V2_CONFIG))
    assert cfg.budget.max_total_prefixes == 20000


# --- валидация ---

def test_missing_router_section(tmp_path):
    with pytest.raises(ConfigError, match="router"):
        load_config(write_config(tmp_path, "services: {}\n"))


def test_missing_as_number(tmp_path):
    with pytest.raises(ConfigError, match="as_number"):
        load_config(write_config(tmp_path, "router:\n  services: {}\n"))


def test_service_without_any_source(tmp_path):
    """Сервис обязан иметь хоть один источник: ASN, домены, geosite или geoip."""
    with pytest.raises(ConfigError, match="empty"):
        load_config(write_config(tmp_path, """
            router:
              as_number: 65001
              services:
                broken: {}
        """))


def test_floating_ref_rejected(tmp_path):
    """Пиннинг фида только на релиз или sha. Ветка отклоняется."""
    with pytest.raises(ConfigError, match="ref"):
        load_config(write_config(tmp_path, """
            version: 2
            router:
              as_number: 65001
            feeds:
              geosite:
                url: "https://example.invalid/x.txt"
                ref: main
            services:
              youtube:
                domains: [youtube.com]
        """))


@pytest.mark.parametrize("bad_asn", ["notanumber", -5, 0, 4294967296])
def test_invalid_asn_rejected(tmp_path, bad_asn):
    with pytest.raises(ConfigError, match="AS"):
        load_config(write_config(tmp_path, f"""
            router:
              as_number: 65001
              services:
                youtube:
                  as_numbers: [{bad_asn!r}]
        """))


def test_invalid_geoip_mode(tmp_path):
    with pytest.raises(ConfigError, match="mode"):
        load_config(write_config(tmp_path, """
            version: 2
            router:
              as_number: 65001
            services:
              youtube:
                domains: [youtube.com]
                geoip:
                  categories: [google]
                  mode: nonsense
        """))


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(str(tmp_path / "nope.yaml"))


def test_malformed_yaml(tmp_path):
    with pytest.raises(ConfigError):
        load_config(write_config(tmp_path, "router: [unclosed\n"))
