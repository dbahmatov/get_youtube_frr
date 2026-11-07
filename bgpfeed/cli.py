"""Точка входа bgpfeed.

Три команды:

* `run` — полный проход и анонс во FRR. Для v1-конфига (сервисы без доменов)
  это ровно прежнее поведение: развернуть указанные ASN из IRR.
* `discover` — тот же проход, но без единого касания роутера. Основной
  инструмент, когда надо понять, что вообще будет анонсировано.
* `show` — объяснение решения: какие ASN найдены, почему каждая попала в
  свой разряд и во сколько маршрутов обошлась.

`--dry-run`, `--config` и `--withdraw` описаны в README давно, но до сих пор
не существовали в коде: в старом `main()` не было argparse вообще.
"""

from __future__ import annotations

import argparse
import sys
from typing import Callable, List, Optional, Sequence, Tuple

from loguru import logger

from . import discover, frr
from .config import Config, load_config
from .errors import AnnouncementError, BgpfeedError, ConfigError, FetchError
from .feeds import fetcher as feed_fetcher
from .feeds import geoip as geoip_feed
from .feeds import geosite as geosite_feed
from .guards import guard_and_summarize
from .state import load_state, save_state
from .summarize import Network

EXIT_OK = 0
EXIT_ERROR = 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bgpfeed",
        description="Собирает префиксы сервисов и анонсирует их во FRR.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="собрать префиксы и анонсировать их во FRR")
    _add_common_arguments(run)
    run.add_argument(
        "--dry-run", action="store_true",
        help="показать, что было бы отправлено во FRR, но ничего не менять",
    )
    run.add_argument(
        "--withdraw", action="store_true", help="снять анонс вместо его установки"
    )

    _add_common_arguments(subparsers.add_parser(
        "discover", help="собрать префиксы и показать результат, не трогая FRR"
    ))

    show = subparsers.add_parser("show", help="объяснить принятые решения")
    show.add_argument("subject", choices=["asns", "prefixes"],
                      help="что показать: разбор по ASN или итоговые префиксы")
    _add_common_arguments(show)

    feeds = subparsers.add_parser("feeds", help="обновить или показать кэш фидов")
    feed_actions = feeds.add_subparsers(dest="feeds_action", required=True)
    update = feed_actions.add_parser("update", help="принудительно обновить фиды")
    update.add_argument("--config", default="config.yaml", help="путь к config.yaml")
    feed_show = feed_actions.add_parser("show", help="показать состояние кэша")
    feed_show.add_argument("--config", default="config.yaml", help="путь к config.yaml")
    feed_show.add_argument("--category", default=None, help="показать одну категорию")

    return parser


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config", default="config.yaml",
        help="путь к config.yaml (по умолчанию: config.yaml)",
    )
    parser.add_argument(
        "--service", default=None, help="обработать только один сервис из конфига"
    )


def collect(config: Config, service_name: Optional[str]) -> List[discover.ServiceReport]:
    """Прогоняет конвейер по выбранным сервисам.

    Состояние читается один раз и записывается один раз в конце: так
    накопленное за прогон не теряется, сколько бы сервисов ни было.
    """
    services = [config.service(service_name)] if service_name else list(config.services)
    state = load_state(config.state_file)
    feeds_fn = _feed_loader(config)

    reports = []
    for service in services:
        state.sync_manual(service.name, service.as_numbers)
        state.expire(service.name, service.state_policy)
        reports.append(discover.discover_service(
            service, state=state, budget=config.budget, guards=config.guards,
            feeds_fn=feeds_fn,
        ))

    save_state(state, config.state_file)
    return reports


def _feed_loader(config: Config) -> Callable[[str, str], str]:
    """Собирает единый загрузчик geosite/geoip из настроек конфига."""
    def load(kind: str, category: str) -> str:
        source = getattr(config.feeds, kind, None)
        if source is None:
            raise BgpfeedError(f"feeds.{kind} is not configured")
        return feed_fetcher.fetch_category(source, category, config.feeds)

    return load


def _configured_categories(config: Config) -> List[Tuple[str, str]]:
    """Уникальные категории в порядке их появления в конфиге."""
    result: List[Tuple[str, str]] = []
    for service in config.services:
        if service.geosite:
            result.extend(("geosite", name) for name in service.geosite.categories)
        if service.geoip:
            result.extend(("geoip", name) for name in service.geoip.categories)
    return list(dict.fromkeys(result))


def merge_prefixes(
    reports: Sequence[discover.ServiceReport],
    config: Config,
    previous: Optional[Sequence[Network]] = None,
) -> List[Network]:
    """Сводит префиксы всех сервисов в один набор.

    Схлопывание повторяется поверх объединения: сервисы часто делят
    инфраструктуру, и их блоки нередко склеиваются между собой.
    """
    collected: List[Network] = []
    for report in reports:
        collected.extend(prefix for prefix in report.prefixes if prefix.version == 4)
    return guard_and_summarize(collected, config.guards, previous=previous)


def run_command(config: Config, args: argparse.Namespace) -> int:
    if args.service and args.withdraw:
        raise ConfigError("--service cannot be combined with --withdraw")

    reports = collect(config, args.service)
    state = load_state(config.state_file)
    managed = set(state.managed())
    current = None
    if args.withdraw and any(
        prefix.version == 4 for report in reports for prefix in report.prefixes
    ):
        current = frr.get_configured_networks(config.as_number)
    previous = [n for n in current or () if str(n) in managed]
    prefixes = merge_prefixes(reports, config, previous=previous)
    logger.info("total: {} prefix(es) across {} service(s)", len(prefixes), len(reports))

    if not prefixes:
        raise AnnouncementError(
            "refusing to change FRR: discovery produced an empty prefix set"
        )

    if not args.withdraw:
        scripts = frr.announce(config.as_number, prefixes, dry_run=args.dry_run)
        _print_dry_run(scripts, args.dry_run)
        if not args.dry_run:
            state.set_managed(managed | {str(p) for p in prefixes})
            save_state(state, config.state_file)
        return EXIT_OK

    assert current is not None  # Непустой withdraw уже прочитал текущий набор FRR.
    plan = frr.reconciliation_diff(current=current, desired=prefixes)
    foreign = [n for n in plan.to_remove if str(n) not in managed]
    if foreign:
        logger.warning(
            "frr: refusing to withdraw {} untracked network(s): {}",
            len(foreign), ", ".join(str(n) for n in foreign[:5]),
        )
        plan = frr.ReconciliationPlan(
            to_add=plan.to_add,
            to_remove=[n for n in plan.to_remove if str(n) in managed],
        )
    logger.info(
        "frr: reconciliation current={} desired={} add={} remove={}",
        len(current), len(prefixes), len(plan.to_add), len(plan.to_remove),
    )

    if plan.to_add:
        scripts = frr.announce(
            config.as_number, plan.to_add, dry_run=args.dry_run,
        )
        _print_dry_run(scripts, args.dry_run)
    if plan.to_remove:
        scripts = frr.withdraw(
            config.as_number, plan.to_remove, dry_run=args.dry_run,
        )
        _print_dry_run(scripts, args.dry_run)
    if not args.dry_run:
        state.set_managed(prefixes)
        save_state(state, config.state_file)
    return EXIT_OK


def _print_dry_run(scripts: Sequence[str], dry_run: bool) -> None:
    if dry_run:
        for script in scripts:
            print(script)


def discover_command(config: Config, args: argparse.Namespace) -> int:
    reports = collect(config, args.service)
    for report in reports:
        print(f"\n{report.service}: {len(report.prefixes)} prefix(es) from "
              f"{len(report.addresses)} resolved address(es)")
        _print_verdicts(report)
        if report.resolve_failed:
            print(f"  {len(report.resolve_failed)} hostname(s) failed to resolve")
    return EXIT_OK


def show_command(config: Config, args: argparse.Namespace) -> int:
    reports = collect(config, args.service)
    for report in reports:
        print(f"\n=== {report.service} ===")
        if args.subject == "asns":
            _print_verdicts(report)
        else:
            for prefix in report.prefixes:
                if prefix.version != 4:
                    continue
                print(prefix)
    return EXIT_OK


def feeds_command(config: Config, args: argparse.Namespace) -> int:
    """Обновляет настроенные категории либо показывает состояние их кэша."""
    categories = [
        item for item in _configured_categories(config)
        if args.feeds_action != "show" or args.category is None or item[1] == args.category
    ]
    if args.feeds_action == "update":
        for kind, category in categories:
            source = getattr(config.feeds, kind)
            if source is None:
                logger.warning("feeds.{} is not configured; skipping {}", kind, category)
                continue
            loader = lambda name: feed_fetcher.fetch_category(
                source, name, config.feeds, force_refresh=True,
            )
            if kind == "geosite":
                loaded = geosite_feed.load_category(category, loader)
                if loaded.missing:
                    raise FetchError(
                        f"geosite:{category}: missing categories: "
                        + ", ".join(sorted(loaded.missing))
                    )
                count = len(loaded.all_names)
            else:
                count = _entry_count(kind, loader(category))
            print(f"{kind}:{category} ref={source.ref} {count} entries")
        return EXIT_OK

    for kind, category in categories:
        source = getattr(config.feeds, kind)
        if source is None:
            print(f"{kind}:{category} source not configured")
            continue
        info = feed_fetcher.cached_category_info(source, category, config.feeds)
        if info is None:
            print(f"{kind}:{category} ref={source.ref} cache=missing 0 entries")
            continue
        age, body = info
        print(f"{kind}:{category} ref={source.ref} age={_format_age(age)} "
              f"{_entry_count(kind, body)} entries")
    return EXIT_OK


def _entry_count(kind: str, body: str) -> int:
    if kind == "geoip":
        return len(geoip_feed.parse(body))
    parsed = geosite_feed.parse(body)
    return len(parsed.suffixes) + len(parsed.hostnames)


def _format_age(seconds: float) -> str:
    if seconds < 3600:
        return f"{int(seconds // 60)}m"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h"
    return f"{int(seconds // 86400)}d"


def _print_verdicts(report: discover.ServiceReport) -> None:
    for verdict in sorted(report.verdicts, key=lambda v: v.asn):
        cost = "?" if verdict.prefix_count == float("inf") else f"{verdict.prefix_count:g}"
        print(f"  AS{verdict.asn:<8} {verdict.tier:<8} "
              f"{len(verdict.seen_ips):>4} IP {cost:>6} routes  {verdict.reason}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        config = load_config(args.config)
        _configure_logging(config)
        if args.command == "run":
            return run_command(config, args)
        if args.command == "discover":
            return discover_command(config, args)
        if args.command == "feeds":
            return feeds_command(config, args)
        return show_command(config, args)
    except BgpfeedError as exc:
        logger.error("{}", exc)
        return EXIT_ERROR


def _configure_logging(config: Config) -> None:
    if config.log_file:
        logger.add(config.log_file, rotation="10 MB", retention=5, level="INFO")


if __name__ == "__main__":
    sys.exit(main())
