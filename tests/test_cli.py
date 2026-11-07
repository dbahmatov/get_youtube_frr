"""Тесты разбора аргументов и склейки команд.

Отдельный повод для этого файла: README давно описывает флаги `--dry-run`,
`--config`, `--withdraw`, а в `main()` старого скрипта нет argparse вообще —
любой из них падал с ошибкой. Здесь каждый документированный флаг обязан
разбираться.

Сам конвейер проверяется в `test_discover.py`; тут — что команда вызывает
его правильно и что `discover`/`show` не трогают роутер.
"""

import ipaddress
import os
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from bgpfeed import cli
from bgpfeed.discover import ServiceReport
from bgpfeed.errors import AnnouncementError, FetchError
from bgpfeed.select import AsnVerdict
from bgpfeed.state import State, load_state, save_state

CONFIG = """
    router:
      as_number: 65001
      state_file: {state}
      services:
        youtube:
          as_numbers: [36561]
        jetbrains:
          as_numbers: [200019]
"""

FEEDS_CONFIG = """
    version: 2
    router:
      as_number: 65001
      state_file: {state}
    feeds:
      cache_dir: {cache}
      geosite:
        url: https://example.test/geosite/{ref}/{category}
        ref: release-1
      geoip:
        url: https://example.test/geoip/{ref}/{category}
        ref: deadbeef
    services:
      youtube:
        geosite:
          categories: [youtube]
        geoip:
          categories: [google]
          mode: announce
"""


@pytest.fixture
def config_path(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(textwrap.dedent(
        CONFIG.format(state=str(tmp_path / "state.json"))
    ))
    return str(path)


@pytest.fixture
def feeds_config_path(tmp_path):
    path = tmp_path / "feeds.yaml"
    path.write_text(textwrap.dedent(FEEDS_CONFIG.format(
        state=str(tmp_path / "state.json"), cache=str(tmp_path / "feeds"),
        ref="{ref}", category="{category}",
    )))
    return str(path)


def nets(*cidrs):
    return [ipaddress.ip_network(c) for c in cidrs]


def seed_managed(tmp_path, *cidrs):
    state = State()
    state.set_managed(nets(*cidrs))
    save_state(state, str(tmp_path / "state.json"))


@pytest.fixture
def fake_pipeline(monkeypatch):
    """Подменяет конвейер, записывая, по каким сервисам его звали."""
    calls = []

    def factory(prefixes=None, error=None, verdicts=()):
        def fake(service, state, budget, guards, **kwargs):
            calls.append(service.name)
            if error is not None:
                raise error
            return ServiceReport(
                service=service.name,
                prefixes=list(prefixes if prefixes is not None else nets("8.8.8.0/24")),
                verdicts=list(verdicts),
            )

        monkeypatch.setattr(cli.discover, "discover_service", fake)
        return calls

    return factory


@pytest.fixture
def no_frr(monkeypatch):
    """Ловит любые обращения к FRR."""
    calls = {"announce": [], "withdraw": [], "current": []}
    monkeypatch.setattr(cli.frr, "announce",
                        lambda asn, prefixes, **kw: calls["announce"].append(
                            {"prefixes": list(prefixes), **kw}
                        ) or [])
    monkeypatch.setattr(cli.frr, "withdraw",
                        lambda asn, prefixes, **kw: calls["withdraw"].append(
                            {"prefixes": list(prefixes), **kw}
                        ) or [])
    monkeypatch.setattr(cli.frr, "get_configured_networks",
                        lambda asn: calls["current"].append(asn) or [])
    return calls


# --- разбор аргументов ---

@pytest.mark.parametrize("argv", [
    ["run"],
    ["run", "--dry-run"],
    ["run", "--config", "config.yaml"],
    ["run", "--withdraw"],
    ["run", "--service", "youtube"],
    ["run", "--dry-run", "--config", "x.yaml", "--service", "youtube"],
])
def test_documented_flags_parse(argv):
    assert cli.build_parser().parse_args(argv).command == "run"


def test_config_defaults_to_repo_file():
    assert cli.build_parser().parse_args(["run"]).config == "config.yaml"


def test_dry_run_defaults_off():
    assert cli.build_parser().parse_args(["run"]).dry_run is False


def test_unknown_flag_rejected():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["run", "--nonsense"])


def test_no_command_exits():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args([])


def test_discover_has_no_dry_run_flag():
    """`discover` и так ничего не меняет — флаг был бы обманом."""
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["discover", "--dry-run"])


def test_show_requires_a_subject():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["show"])


@pytest.mark.parametrize("subject", ["asns", "prefixes"])
def test_show_subjects_parse(subject):
    assert cli.build_parser().parse_args(["show", subject]).subject == subject


def test_show_rejects_unknown_subject():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["show", "everything"])


@pytest.mark.parametrize("argv", [
    ["feeds", "update"],
    ["feeds", "show"],
    ["feeds", "show", "--category", "youtube"],
    ["feeds", "update", "--config", "feeds.yaml"],
])
def test_feed_commands_parse(argv):
    args = cli.build_parser().parse_args(argv)
    assert args.command == "feeds"


def test_feeds_requires_an_action():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["feeds"])


# --- run ---

def test_run_announces_collected_prefixes(config_path, fake_pipeline, no_frr):
    fake_pipeline()
    assert cli.main(["run", "--config", config_path, "--dry-run"]) == 0
    assert no_frr["announce"]


def test_run_passes_dry_run_through(config_path, fake_pipeline, no_frr):
    fake_pipeline()
    cli.main(["run", "--config", config_path, "--dry-run"])
    assert no_frr["announce"][0]["dry_run"] is True


def test_run_covers_every_service(config_path, fake_pipeline, no_frr):
    calls = fake_pipeline()
    cli.main(["run", "--config", config_path, "--dry-run"])
    assert calls == ["youtube", "jetbrains"]


def test_service_filter_limits_work(config_path, fake_pipeline, no_frr):
    calls = fake_pipeline()
    cli.main(["run", "--config", config_path, "--service", "youtube", "--dry-run"])
    assert calls == ["youtube"]


def test_service_filter_with_withdraw_is_rejected_before_work(
    config_path, fake_pipeline, no_frr, monkeypatch,
):
    """Один сервис не даёт права считать чужие network устаревшими."""
    calls = fake_pipeline()
    monkeypatch.setattr(
        cli.frr, "get_configured_networks", lambda asn: nets("1.1.1.0/24"),
    )

    assert cli.main([
        "run", "--config", config_path, "--service", "youtube", "--withdraw",
    ]) != 0
    assert calls == []
    assert no_frr == {"announce": [], "withdraw": [], "current": []}


def test_prefixes_merged_across_services(config_path, monkeypatch, no_frr):
    """Сервисы часто делят инфраструктуру — их блоки схлопываются вместе."""
    halves = iter([nets("8.8.8.0/25"), nets("8.8.8.128/25")])

    def fake(service, state, budget, guards, **kwargs):
        return ServiceReport(service=service.name, prefixes=list(next(halves)))

    monkeypatch.setattr(cli.discover, "discover_service", fake)
    seen = {}
    monkeypatch.setattr(cli.frr, "announce",
                        lambda asn, prefixes, **kw: seen.setdefault("p", list(prefixes)))
    cli.main(["run", "--config", config_path, "--dry-run"])
    assert seen["p"] == nets("8.8.8.0/24")


def test_ipv6_is_collected_but_not_sent_to_frr(config_path, monkeypatch, no_frr):
    """v1 копит AAAA в state, но IPv6-анонс остаётся вне текущего scope."""
    def fake(service, state, budget, guards, **kwargs):
        return ServiceReport(
            service=service.name,
            prefixes=nets("8.8.8.0/24", "2001:4860::/32"),
        )

    monkeypatch.setattr(cli.discover, "discover_service", fake)
    seen = {}
    monkeypatch.setattr(cli.frr, "announce",
                        lambda asn, prefixes, **kw: seen.setdefault("p", list(prefixes)) or [])
    assert cli.main(["run", "--config", config_path, "--dry-run"]) == 0
    assert seen["p"] == nets("8.8.8.0/24")


def test_guards_applied_to_merged_result(config_path, monkeypatch, no_frr):
    def fake(service, state, budget, guards, **kwargs):
        return ServiceReport(service=service.name, prefixes=nets("0.0.0.0/0"))

    monkeypatch.setattr(cli.discover, "discover_service", fake)
    seen = {}
    monkeypatch.setattr(cli.frr, "announce",
                        lambda asn, prefixes, **kw: seen.setdefault("p", list(prefixes)))
    assert cli.main(["run", "--config", config_path, "--dry-run"]) != 0
    assert seen == {}


def test_merge_keeps_specific_parts_of_too_wide_collapse(
    config_path, monkeypatch, no_frr,
):
    def fake(service, state, budget, guards, **kwargs):
        return ServiceReport(
            service=service.name,
            prefixes=nets("8.0.0.0/10", "8.64.0.0/10"),
        )

    monkeypatch.setattr(cli.discover, "discover_service", fake)
    seen = {}
    monkeypatch.setattr(
        cli.frr, "announce",
        lambda asn, prefixes, **kw: seen.setdefault("p", list(prefixes)) or [],
    )
    assert cli.main(["run", "--config", config_path, "--dry-run"]) == 0
    assert seen["p"] == nets("8.0.0.0/10", "8.64.0.0/10")


def test_withdraw_reconciles_current_networks(
    config_path, fake_pipeline, no_frr, monkeypatch, tmp_path,
):
    seed_managed(tmp_path, "1.1.1.0/24")
    fake_pipeline(prefixes=nets("8.8.8.0/24", "9.9.9.0/24"))
    monkeypatch.setattr(
        cli.frr, "get_configured_networks",
        lambda asn: nets("1.1.1.0/24", "8.8.8.0/24"),
    )
    cli.main(["run", "--config", config_path, "--withdraw", "--dry-run"])
    assert no_frr["announce"][0]["prefixes"] == nets("9.9.9.0/24")
    assert no_frr["withdraw"][0]["prefixes"] == nets("1.1.1.0/24")


def test_withdraw_never_removes_untracked_networks(
    config_path, fake_pipeline, no_frr, monkeypatch, tmp_path,
):
    """Ручной или legacy network не принадлежит bgpfeed — только предупредить."""
    fake_pipeline(prefixes=nets("8.8.8.0/24"))
    monkeypatch.setattr(
        cli.frr, "get_configured_networks",
        lambda asn: nets("8.8.8.0/24", "1.1.1.0/24", "2001:4860::/32"),
    )
    warnings = []
    monkeypatch.setattr(
        cli.logger, "warning",
        lambda message, *args: warnings.append(message.format(*args)),
    )

    assert cli.main(["run", "--config", config_path, "--withdraw"]) == 0
    assert no_frr["withdraw"] == []
    assert any("1.1.1.0/24" in message for message in warnings)
    assert any("2001:4860::/32" in message for message in warnings)


def test_run_tracks_announced_prefixes_as_managed(
    config_path, fake_pipeline, no_frr, tmp_path,
):
    fake_pipeline(prefixes=nets("8.8.8.0/24"))
    assert cli.main(["run", "--config", config_path]) == 0
    assert load_state(str(tmp_path / "state.json")).managed() == ("8.8.8.0/24",)


def test_withdraw_refuses_sudden_shrink_with_default_guard(
    config_path, fake_pipeline, no_frr, monkeypatch, tmp_path,
):
    """Переход 4 → 1 похож на частичный сбой, а не на повод снять маршруты."""
    previous = nets("8.8.8.0/24", "8.8.4.0/24", "1.1.1.0/24", "1.0.0.0/24")
    seed_managed(tmp_path, *(str(network) for network in previous))
    fake_pipeline(prefixes=nets("8.8.8.0/24"))
    monkeypatch.setattr(
        cli.frr, "get_configured_networks",
        lambda asn: previous,
    )

    assert cli.main(["run", "--config", config_path, "--withdraw"]) != 0
    assert no_frr["announce"] == []
    assert no_frr["withdraw"] == []


def test_reconciliation_add_failure_prevents_withdraw(
    config_path, fake_pipeline, no_frr, monkeypatch,
):
    fake_pipeline(prefixes=nets("8.8.8.0/24"))
    monkeypatch.setattr(cli.frr, "get_configured_networks",
                        lambda asn: nets("1.1.1.0/24"))
    monkeypatch.setattr(
        cli.frr, "announce",
        lambda *args, **kwargs: (_ for _ in ()).throw(AnnouncementError("add failed")),
    )

    assert cli.main(["run", "--config", config_path, "--withdraw"]) != 0
    assert no_frr["withdraw"] == []


def test_reconciliation_adds_before_removing(
    config_path, fake_pipeline, monkeypatch, tmp_path,
):
    seed_managed(tmp_path, "1.1.1.0/24")
    fake_pipeline(prefixes=nets("8.8.8.0/24"))
    events = []
    monkeypatch.setattr(cli.frr, "get_configured_networks",
                        lambda asn: nets("1.1.1.0/24"))
    monkeypatch.setattr(cli.frr, "announce",
                        lambda *args, **kwargs: events.append("add") or [])
    monkeypatch.setattr(cli.frr, "withdraw",
                        lambda *args, **kwargs: events.append("remove") or [])

    assert cli.main(["run", "--config", config_path, "--withdraw"]) == 0
    assert events == ["add", "remove"]


def test_reconciliation_is_idempotent(
    config_path, fake_pipeline, no_frr, monkeypatch,
):
    fake_pipeline(prefixes=nets("8.8.8.0/24"))
    monkeypatch.setattr(cli.frr, "get_configured_networks",
                        lambda asn: nets("8.8.8.0/24"))

    assert cli.main(["run", "--config", config_path, "--withdraw"]) == 0
    assert no_frr["announce"] == [] and no_frr["withdraw"] == []


def test_empty_import_never_reads_or_changes_frr(config_path, fake_pipeline, no_frr):
    fake_pipeline(prefixes=[])
    assert cli.main(["run", "--config", config_path, "--withdraw"]) != 0
    assert no_frr == {"announce": [], "withdraw": [], "current": []}


def test_reconciliation_dry_run_does_not_apply(config_path, fake_pipeline, no_frr):
    fake_pipeline(prefixes=nets("8.8.8.0/24"))
    assert cli.main([
        "run", "--config", config_path, "--withdraw", "--dry-run",
    ]) == 0
    assert no_frr["announce"][0]["dry_run"] is True


# --- discover и show ---

def test_discover_never_touches_frr(config_path, fake_pipeline, no_frr):
    fake_pipeline()
    assert cli.main(["discover", "--config", config_path]) == 0
    assert no_frr["announce"] == [] and no_frr["withdraw"] == []


def test_show_never_touches_frr(config_path, fake_pipeline, no_frr):
    fake_pipeline()
    assert cli.main(["show", "asns", "--config", config_path]) == 0
    assert no_frr["announce"] == [] and no_frr["withdraw"] == []


def test_show_asns_explains_each_verdict(config_path, fake_pipeline, no_frr, capsys):
    """Находка из спеки: AS36561 подписана как главная ASN YouTube, а даёт 1 маршрут."""
    verdict = AsnVerdict(asn=36561, tier="trusted", reason="1 prefix after collapse",
                         seen_ips=frozenset({"165.85.150.1"}), prefix_count=1)
    fake_pipeline(verdicts=[verdict])
    cli.main(["show", "asns", "--config", config_path])

    out = capsys.readouterr().out
    assert "AS36561" in out
    assert "trusted" in out
    assert "1 prefix after collapse" in out


def test_show_prefixes_lists_them(config_path, fake_pipeline, no_frr, capsys):
    fake_pipeline(prefixes=nets("8.8.8.0/24", "2001:4860::/32"))
    cli.main(["show", "prefixes", "--config", config_path])
    out = capsys.readouterr().out
    assert "8.8.8.0/24" in out
    assert "2001:4860::/32" not in out


def test_unknown_cost_printed_as_question_mark(config_path, fake_pipeline, no_frr, capsys):
    """ASN без данных в IRR: цена неизвестна, и это должно быть видно."""
    verdict = AsnVerdict(asn=64500, tier="limited", reason="no IRR data",
                         seen_ips=frozenset({"1.1.1.1"}), prefix_count=float("inf"))
    fake_pipeline(verdicts=[verdict])
    cli.main(["show", "asns", "--config", config_path])
    assert "?" in capsys.readouterr().out


# --- поведение при сбоях ---

def test_source_failure_exits_nonzero_without_announcing(config_path, fake_pipeline, no_frr):
    """Источник упал — ничего не анонсируем и сообщаем об этом кодом возврата."""
    fake_pipeline(error=FetchError("radb down"))
    assert cli.main(["run", "--config", config_path]) != 0
    assert no_frr["announce"] == []


def test_unknown_service_exits_nonzero(config_path, fake_pipeline, no_frr):
    fake_pipeline()
    assert cli.main(["run", "--config", config_path, "--service", "nope"]) != 0


def test_bad_config_exits_nonzero(tmp_path):
    assert cli.main(["run", "--config", str(tmp_path / "nope.yaml")]) != 0


def test_collect_drops_manual_asn_removed_from_config(
    config_path, fake_pipeline, tmp_path,
):
    state = State()
    state.observe("youtube", asns=[99999], manual=True, now=0)
    save_state(state, str(tmp_path / "state.json"))
    fake_pipeline()

    cli.collect(cli.load_config(config_path), None)

    assert 99999 not in load_state(str(tmp_path / "state.json")).asns("youtube")


def test_state_is_persisted_between_runs(config_path, monkeypatch, no_frr, tmp_path):
    """Накопленное за прогон должно пережить его завершение."""
    def fake(service, state, budget, guards, **kwargs):
        state.observe(service.name, hostnames=["rr1.googlevideo.com"])
        return ServiceReport(service=service.name, prefixes=nets("8.8.8.0/24"))

    monkeypatch.setattr(cli.discover, "discover_service", fake)
    cli.main(["run", "--config", config_path, "--dry-run"])

    state = load_state(str(tmp_path / "state.json"))
    assert "rr1.googlevideo.com" in state.hostnames("youtube")


# --- feeds ---

def test_collect_connects_configured_feeds_to_discovery(feeds_config_path, monkeypatch):
    seen = []

    def fake_fetch(source, category, feeds, **kwargs):
        seen.append((source.ref, category))
        return "youtube.com\n" if category == "youtube" else "8.8.8.0/24\n"

    def fake_discover(service, state, budget, guards, feeds_fn=None, **kwargs):
        assert feeds_fn("geosite", "youtube") == "youtube.com\n"
        assert feeds_fn("geoip", "google") == "8.8.8.0/24\n"
        return ServiceReport(service=service.name)

    monkeypatch.setattr(cli.feed_fetcher, "fetch_category", fake_fetch)
    monkeypatch.setattr(cli.discover, "discover_service", fake_discover)

    cli.collect(cli.load_config(feeds_config_path), None)
    assert seen == [("release-1", "youtube"), ("deadbeef", "google")]


def test_feeds_update_forces_every_configured_category(feeds_config_path, monkeypatch):
    seen = []

    def fake_fetch(source, category, feeds, **kwargs):
        seen.append((source.ref, category, kwargs.get("force_refresh")))
        return "youtube.com\n" if category == "youtube" else "8.8.8.0/24\n"

    monkeypatch.setattr(cli.feed_fetcher, "fetch_category", fake_fetch)
    assert cli.main(["feeds", "update", "--config", feeds_config_path]) == 0
    assert seen == [
        ("release-1", "youtube", True),
        ("deadbeef", "google", True),
    ]


def test_feeds_update_caches_recursive_geosite_categories(feeds_config_path, monkeypatch):
    seen = []

    def fake_fetch(source, category, feeds, **kwargs):
        seen.append(category)
        bodies = {
            "youtube": "include:google-video\nyoutube.com\n",
            "google-video": "googlevideo.com\n",
            "google": "8.8.8.0/24\n",
        }
        return bodies[category]

    monkeypatch.setattr(cli.feed_fetcher, "fetch_category", fake_fetch)
    assert cli.main(["feeds", "update", "--config", feeds_config_path]) == 0
    assert seen == ["youtube", "google-video", "google"]


def test_feeds_update_fails_when_geosite_category_is_missing(
    feeds_config_path, monkeypatch,
):
    def fake_fetch(source, category, feeds, **kwargs):
        if category == "youtube":
            raise FetchError("source down")
        return "8.8.8.0/24\n"

    monkeypatch.setattr(cli.feed_fetcher, "fetch_category", fake_fetch)
    assert cli.main(["feeds", "update", "--config", feeds_config_path]) != 0


def test_feeds_show_reports_ref_age_and_entry_count(feeds_config_path, monkeypatch, capsys):
    monkeypatch.setattr(
        cli.feed_fetcher, "cached_category_info",
        lambda source, category, feeds: (3600.0, "youtube.com\nytimg.com\n")
        if category == "youtube" else (7200.0, "8.8.8.0/24\n"),
    )

    assert cli.main(["feeds", "show", "--config", feeds_config_path]) == 0
    out = capsys.readouterr().out
    assert "geosite:youtube" in out and "release-1" in out and "2 entries" in out
    assert "geoip:google" in out and "deadbeef" in out and "1 entries" in out
    assert "1h" in out and "2h" in out


def test_feeds_show_category_filters_output(feeds_config_path, monkeypatch, capsys):
    monkeypatch.setattr(
        cli.feed_fetcher, "cached_category_info",
        lambda source, category, feeds: (0.0, "youtube.com\n"),
    )
    assert cli.main([
        "feeds", "show", "--category", "youtube", "--config", feeds_config_path,
    ]) == 0
    out = capsys.readouterr().out
    assert "geosite:youtube" in out
    assert "geoip:google" not in out
