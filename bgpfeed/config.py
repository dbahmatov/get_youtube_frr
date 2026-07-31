"""Загрузка и валидация конфига.

Поддерживаются два формата:

* **v1** — то, что лежало в проекте раньше: `router.services.<имя>.as_numbers`
  и больше ничего. Грузится без правок и ведёт себя как прежде: стратегия
  `asn`, никакого резолва, ASN разворачивается из RADB целиком.
* **v2** — доменный конвейер: `geosite`, `geoip`, `domains`, `wildcards`
  плюс общая секция `defaults`, значения которой мёржатся в каждый сервис.

Версия определяется по ключу `version`. Его отсутствие означает v1 — так
существующие установки не ломаются от самого факта обновления.

Все ошибки — `ConfigError` с указанием конкретного поля. `KeyError` наружу
не выпускается: оператор, правящий YAML на роутере, должен видеть, что именно
он сломал.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from typing import Any, Dict, Literal, Optional, Tuple

import yaml

from .errors import ConfigError

Strategy = Literal["hybrid", "asn", "covering_prefix"]
GeoipMode = Literal["announce", "corroborate", "off"]
Corroboration = Literal["off", "soft", "strict"]
OnOverflow = Literal["downgrade", "fail"]

ASN_MAX = 4294967295

# Ветки отклоняются: фид попадает прямо в BGP-анонс, содержимое обязано быть
# воспроизводимым. Допустимы теги релизов и commit sha.
FLOATING_REFS = frozenset({"main", "master", "head", "latest", "trunk", "dev"})


@dataclass(frozen=True)
class Vantage:
    """Сетевая позиция, с которой выполняется резолв.

    Ключевой параметр всего проекта: ответы CDN и адрес GGC-кэша зависят от
    того, откуда пришёл запрос. Резолвить нужно оттуда же, откуда пойдёт
    продакшн-трафик, иначе в анонс попадут чужие адреса.
    """

    source_ip: Optional[str] = None
    interface: Optional[str] = None
    resolvers: Tuple[str, ...] = ("system",)


@dataclass(frozen=True)
class ResolveConfig:
    vantage: Vantage = Vantage()
    record_types: Tuple[str, ...] = ("A", "AAAA")
    rounds: int = 3
    round_delay_sec: float = 2.0
    concurrency: int = 20
    timeout_sec: float = 5.0
    follow_cname: bool = True


@dataclass(frozen=True)
class AsnPolicy:
    min_ips: int = 1
    trusted_max_prefixes: int = 2000
    exclude_asns: Tuple[int, ...] = ()
    trusted_asns: Tuple[int, ...] = ()
    corroboration: Corroboration = "soft"


@dataclass(frozen=True)
class StatePolicy:
    ttl_days: int = 90
    keep_manual_forever: bool = True


@dataclass(frozen=True)
class Guards:
    min_prefix_len: int = 10
    drop_bogons: bool = True
    max_change_ratio: Optional[float] = None


@dataclass(frozen=True)
class Budget:
    max_total_prefixes: int = 20000
    per_service_max: Optional[int] = None
    on_overflow: OnOverflow = "downgrade"


@dataclass(frozen=True)
class GeositeRef:
    categories: Tuple[str, ...]
    exclude_domains: Tuple[str, ...] = ()


@dataclass(frozen=True)
class GeoipRef:
    categories: Tuple[str, ...]
    mode: GeoipMode = "corroborate"


@dataclass(frozen=True)
class Wildcard:
    """Шаблон вида `*.googlevideo.com`.

    Сам по себе не резолвится: хостнеймы под ним генерируются динамически и
    неперечислимы. `samples` — известные представители, с которых начинается
    накопление; дальше состояние пополняется тем, что реально встретилось.
    """

    pattern: str
    samples: Tuple[str, ...] = ()


@dataclass(frozen=True)
class FeedSource:
    url: str
    ref: str
    sha256: Optional[str] = None


@dataclass(frozen=True)
class FeedsConfig:
    cache_dir: str = "state/feeds"
    refresh_days: int = 7
    offline_ok: bool = True
    geosite: Optional[FeedSource] = None
    geoip: Optional[FeedSource] = None


@dataclass(frozen=True)
class Service:
    name: str
    as_numbers: Tuple[int, ...] = ()
    domains: Tuple[str, ...] = ()
    wildcards: Tuple[Wildcard, ...] = ()
    geosite: Optional[GeositeRef] = None
    geoip: Optional[GeoipRef] = None
    strategy: Strategy = "hybrid"
    asn_policy: AsnPolicy = AsnPolicy()
    resolve: ResolveConfig = ResolveConfig()
    state_policy: StatePolicy = StatePolicy()


@dataclass(frozen=True)
class Config:
    as_number: int
    services: Tuple[Service, ...]
    log_file: str = "routes.log"
    state_file: str = "state/bgpfeed.json"
    feeds: FeedsConfig = FeedsConfig()
    guards: Guards = Guards()
    budget: Budget = Budget()
    version: int = 1

    def service(self, name: str) -> Service:
        for svc in self.services:
            if svc.name == name:
                return svc
        raise ConfigError(f"service {name!r} not found in config")


# --- вспомогательные разборщики ---


def _require_mapping(value: Any, field: str) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"field {field!r} must be a mapping, got {type(value).__name__}")
    return value


def _as_tuple(value: Any, field: str) -> Tuple[Any, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)) or not hasattr(value, "__iter__"):
        raise ConfigError(f"field {field!r} must be a list")
    return tuple(value)


def _parse_asn(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"invalid AS number {value!r} in {field!r}: must be an integer")
    if not 1 <= value <= ASN_MAX:
        raise ConfigError(f"invalid AS number {value!r} in {field!r}: out of range 1..{ASN_MAX}")
    return value


def _parse_asn_list(value: Any, field: str) -> Tuple[int, ...]:
    return tuple(_parse_asn(item, field) for item in _as_tuple(value, field))


def _parse_choice(value: Any, allowed: Tuple[str, ...], field: str, default: str) -> str:
    if value is None:
        return default
    if value not in allowed:
        raise ConfigError(
            f"invalid {field!r} value {value!r}: expected one of {', '.join(allowed)}"
        )
    return value


def _parse_feed_source(raw: Any, name: str) -> Optional[FeedSource]:
    data = _require_mapping(raw, f"feeds.{name}")
    if not data:
        return None
    url = data.get("url")
    if not url:
        raise ConfigError(f"feeds.{name}.url is required when the section is present")
    ref = data.get("ref")
    if not ref:
        raise ConfigError(
            f"feeds.{name}.ref is required: pin the feed to a release tag or commit sha"
        )
    if str(ref).lower() in FLOATING_REFS:
        raise ConfigError(
            f"feeds.{name}.ref {ref!r} is a floating branch; "
            "pin to a release tag or commit sha so announcements stay reproducible"
        )
    return FeedSource(url=str(url), ref=str(ref), sha256=data.get("sha256"))


def _parse_feeds(raw: Any) -> FeedsConfig:
    data = _require_mapping(raw, "feeds")
    base = FeedsConfig()
    return FeedsConfig(
        cache_dir=data.get("cache_dir", base.cache_dir),
        refresh_days=data.get("refresh_days", base.refresh_days),
        offline_ok=data.get("offline_ok", base.offline_ok),
        geosite=_parse_feed_source(data.get("geosite"), "geosite"),
        geoip=_parse_feed_source(data.get("geoip"), "geoip"),
    )


def _parse_vantage(raw: Any, base: Vantage) -> Vantage:
    data = _require_mapping(raw, "resolve.vantage")
    if not data:
        return base
    resolvers = data.get("resolvers")
    return Vantage(
        source_ip=data.get("source_ip", base.source_ip),
        interface=data.get("interface", base.interface),
        resolvers=tuple(str(r) for r in _as_tuple(resolvers, "resolvers")) or base.resolvers,
    )


def _parse_resolve(raw: Any, base: ResolveConfig) -> ResolveConfig:
    data = _require_mapping(raw, "resolve")
    if not data:
        return base
    record_types = _as_tuple(data.get("record_types"), "record_types")
    return ResolveConfig(
        vantage=_parse_vantage(data.get("vantage"), base.vantage),
        record_types=tuple(str(t).upper() for t in record_types) or base.record_types,
        rounds=data.get("rounds", base.rounds),
        round_delay_sec=data.get("round_delay_sec", base.round_delay_sec),
        concurrency=data.get("concurrency", base.concurrency),
        timeout_sec=data.get("timeout_sec", base.timeout_sec),
        follow_cname=data.get("follow_cname", base.follow_cname),
    )


def _parse_asn_policy(raw: Any, base: AsnPolicy, field: str) -> AsnPolicy:
    data = _require_mapping(raw, field)
    if not data:
        return base
    return AsnPolicy(
        min_ips=data.get("min_ips", base.min_ips),
        trusted_max_prefixes=data.get("trusted_max_prefixes", base.trusted_max_prefixes),
        exclude_asns=_parse_asn_list(data.get("exclude_asns"), f"{field}.exclude_asns")
        or base.exclude_asns,
        trusted_asns=_parse_asn_list(data.get("trusted_asns"), f"{field}.trusted_asns")
        or base.trusted_asns,
        corroboration=_parse_choice(
            data.get("corroboration"), ("off", "soft", "strict"),
            f"{field}.corroboration", base.corroboration,
        ),
    )


def _parse_state_policy(raw: Any, base: StatePolicy) -> StatePolicy:
    data = _require_mapping(raw, "state")
    if not data:
        return base
    return StatePolicy(
        ttl_days=data.get("ttl_days", base.ttl_days),
        keep_manual_forever=data.get("keep_manual_forever", base.keep_manual_forever),
    )


def _parse_guards(raw: Any) -> Guards:
    data = _require_mapping(raw, "guards")
    base = Guards()
    return Guards(
        min_prefix_len=data.get("min_prefix_len", base.min_prefix_len),
        drop_bogons=data.get("drop_bogons", base.drop_bogons),
        max_change_ratio=data.get("max_change_ratio", base.max_change_ratio),
    )


def _parse_budget(raw: Any) -> Budget:
    data = _require_mapping(raw, "budget")
    base = Budget()
    return Budget(
        max_total_prefixes=data.get("max_total_prefixes", base.max_total_prefixes),
        per_service_max=data.get("per_service_max", base.per_service_max),
        on_overflow=_parse_choice(
            data.get("on_overflow"), ("downgrade", "fail"), "budget.on_overflow",
            base.on_overflow,
        ),
    )


def _parse_geosite(raw: Any, service: str) -> Optional[GeositeRef]:
    data = _require_mapping(raw, f"services.{service}.geosite")
    if not data:
        return None
    categories = tuple(str(c) for c in _as_tuple(data.get("categories"), "categories"))
    if not categories:
        raise ConfigError(f"services.{service}.geosite.categories must not be empty")
    excluded = tuple(str(d) for d in _as_tuple(data.get("exclude_domains"), "exclude_domains"))
    return GeositeRef(categories=categories, exclude_domains=excluded)


def _parse_geoip(raw: Any, service: str) -> Optional[GeoipRef]:
    data = _require_mapping(raw, f"services.{service}.geoip")
    if not data:
        return None
    categories = tuple(str(c) for c in _as_tuple(data.get("categories"), "categories"))
    if not categories:
        raise ConfigError(f"services.{service}.geoip.categories must not be empty")
    mode = _parse_choice(
        data.get("mode"), ("announce", "corroborate", "off"),
        f"services.{service}.geoip.mode", "corroborate",
    )
    return GeoipRef(categories=categories, mode=mode)


def _parse_wildcards(raw: Any, service: str) -> Tuple[Wildcard, ...]:
    result = []
    for entry in _as_tuple(raw, f"services.{service}.wildcards"):
        data = _require_mapping(entry, f"services.{service}.wildcards[]")
        pattern = data.get("pattern")
        if not pattern:
            raise ConfigError(f"services.{service}.wildcards[].pattern is required")
        samples = tuple(str(s) for s in _as_tuple(data.get("samples"), "samples"))
        result.append(Wildcard(pattern=str(pattern), samples=samples))
    return tuple(result)


@dataclass(frozen=True)
class _Defaults:
    """Раскрытая секция `defaults`, готовая к вливанию в каждый сервис."""

    strategy: Strategy
    asn_policy: AsnPolicy
    resolve: ResolveConfig
    state_policy: StatePolicy


def _parse_defaults(raw: Any, is_v1: bool) -> _Defaults:
    data = _require_mapping(raw, "defaults")
    # v1 не знает про резолв: сервисы разворачиваются из ASN ровно как раньше.
    fallback_strategy: Strategy = "asn" if is_v1 else "hybrid"
    return _Defaults(
        strategy=_parse_choice(
            data.get("strategy"), ("hybrid", "asn", "covering_prefix"),
            "defaults.strategy", fallback_strategy,
        ),
        asn_policy=_parse_asn_policy(data.get("asn_selection"), AsnPolicy(), "defaults.asn_selection"),
        resolve=_parse_resolve(data.get("resolve"), ResolveConfig()),
        state_policy=_parse_state_policy(data.get("state"), StatePolicy()),
    )


def _parse_service(name: str, raw: Any, defaults: _Defaults, is_v1: bool) -> Service:
    data = _require_mapping(raw, f"services.{name}")

    as_numbers = _parse_asn_list(data.get("as_numbers"), f"services.{name}.as_numbers")
    domains = tuple(str(d) for d in _as_tuple(data.get("domains"), f"services.{name}.domains"))
    wildcards = _parse_wildcards(data.get("wildcards"), name)
    geosite = _parse_geosite(data.get("geosite"), name)
    geoip = _parse_geoip(data.get("geoip"), name)

    if not (as_numbers or domains or wildcards or geosite or geoip):
        raise ConfigError(
            f"services.{name} is empty: give it at least one source "
            "(as_numbers, domains, wildcards, geosite or geoip)"
        )

    asn_policy = _parse_asn_policy(
        data.get("asn_selection"), defaults.asn_policy, f"services.{name}.asn_selection"
    )
    # Сохраняем явное происхождение ASN для отчёта и обхода min_ips.
    if as_numbers:
        merged = tuple(dict.fromkeys(asn_policy.trusted_asns + as_numbers))
        asn_policy = replace(asn_policy, trusted_asns=merged)

    return Service(
        name=name,
        as_numbers=as_numbers,
        domains=domains,
        wildcards=wildcards,
        geosite=geosite,
        geoip=geoip,
        strategy=_parse_choice(
            data.get("strategy"), ("hybrid", "asn", "covering_prefix"),
            f"services.{name}.strategy", defaults.strategy,
        ),
        asn_policy=asn_policy,
        resolve=_parse_resolve(data.get("resolve"), defaults.resolve),
        state_policy=_parse_state_policy(data.get("state"), defaults.state_policy),
    )


def load_config(config_path: str = "config.yaml") -> Config:
    """Читает YAML и возвращает провалидированный `Config`.

    Определяет версию формата по ключу `version`: без него конфиг считается
    v1 и грузится в режиме обратной совместимости.
    """
    if not os.path.exists(config_path):
        raise ConfigError(f"config file not found: {config_path}")

    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ConfigError(f"malformed YAML in {config_path}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read {config_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"{config_path}: top level must be a mapping")

    version = raw.get("version", 1)
    is_v1 = "version" not in raw

    router = _require_mapping(raw.get("router"), "router")
    if not router:
        raise ConfigError("section 'router' is required")
    if "as_number" not in router:
        raise ConfigError("field 'router.as_number' is required")
    local_asn = _parse_asn(router["as_number"], "router.as_number")

    # Сервисы жили в router.services (v1) и переехали на верхний уровень (v2).
    # Принимаем оба размещения: так v2-конфиг можно собирать постепенно.
    services_raw = raw.get("services")
    if services_raw is None:
        services_raw = router.get("services")
    services_map = _require_mapping(services_raw, "services")
    if not services_map:
        raise ConfigError("no services defined: nothing to announce")

    defaults = _parse_defaults(raw.get("defaults"), is_v1)
    services = tuple(
        _parse_service(name, body, defaults, is_v1)
        for name, body in services_map.items()
    )

    return Config(
        as_number=local_asn,
        services=services,
        log_file=router.get("log_file", "routes.log"),
        state_file=router.get("state_file", "state/bgpfeed.json"),
        feeds=_parse_feeds(raw.get("feeds")),
        guards=_parse_guards(raw.get("guards") or (raw.get("defaults") or {}).get("guards")),
        budget=_parse_budget(raw.get("budget") or (raw.get("defaults") or {}).get("budget")),
        version=version,
    )
