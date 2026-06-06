import ipaddress
import os
import sys
import tempfile
import threading

import pytest
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from getroutes import (
    AnnouncementError,
    ConfigError,
    SetupError,
    build_vtysh_command,
    fetch_routes,
    load_config,
    normalize_ipv4_routes,
    prepare_routes,
    summarize_routes,
)


# --- normalize_ipv4_routes ---

def test_normalize_valid_ipv4():
    result = normalize_ipv4_routes(["10.0.0.0/8", "192.168.1.0/24"])
    assert len(result) == 2
    assert all(isinstance(n, ipaddress.IPv4Network) for n in result)


def test_normalize_drops_ipv6():
    result = normalize_ipv4_routes(["10.0.0.0/8", "2001:db8::/32"])
    assert len(result) == 1
    assert str(result[0]) == "10.0.0.0/8"


def test_normalize_deduplicates():
    result = normalize_ipv4_routes(["10.0.0.0/8", "10.0.0.0/8", "10.0.0.1/8"])
    assert len(result) == 1


def test_normalize_invalid_skipped():
    result = normalize_ipv4_routes(["not-a-prefix", "10.0.0.0/8"])
    assert len(result) == 1
    assert str(result[0]) == "10.0.0.0/8"


def test_normalize_empty():
    assert normalize_ipv4_routes([]) == []


def test_normalize_sorted():
    result = normalize_ipv4_routes(["192.168.0.0/16", "10.0.0.0/8"])
    assert result[0] < result[1]


# --- summarize_routes ---

def test_summarize_collapses_adjacent():
    networks = normalize_ipv4_routes(["10.0.0.0/25", "10.0.0.128/25"])
    result = summarize_routes(networks)
    assert result == ["10.0.0.0/24"]


def test_summarize_no_collapse_when_not_adjacent():
    networks = normalize_ipv4_routes(["10.0.0.0/24", "10.0.2.0/24"])
    result = summarize_routes(networks)
    assert len(result) == 2


def test_summarize_empty():
    result = summarize_routes([])
    assert result == []


# --- prepare_routes ---

def test_prepare_no_summarize_returns_normalized():
    result = prepare_routes(["10.0.0.0/25", "10.0.0.128/25"], no_summarize=True)
    assert "10.0.0.0/25" in result
    assert "10.0.0.128/25" in result
    assert "10.0.0.0/24" not in result


def test_prepare_with_summarize_collapses():
    result = prepare_routes(["10.0.0.0/25", "10.0.0.128/25"], no_summarize=False)
    assert result == ["10.0.0.0/24"]


def test_prepare_drops_ipv6():
    result = prepare_routes(["10.0.0.0/8", "2001:db8::/32"], no_summarize=True)
    assert len(result) == 1
    assert result[0] == "10.0.0.0/8"


def test_prepare_empty_returns_empty():
    assert prepare_routes([], no_summarize=False) == []
    assert prepare_routes([], no_summarize=True) == []


# --- build_vtysh_command ---

def test_build_vtysh_command_announce():
    cmd = build_vtysh_command(65001, ["10.0.0.0/8", "192.168.0.0/16"])
    assert "vtysh" in cmd
    assert "router bgp 65001" in cmd
    assert "network 10.0.0.0/8" in cmd
    assert "network 192.168.0.0/16" in cmd
    assert cmd[-1] == "end"


def test_build_vtysh_command_withdraw():
    cmd = build_vtysh_command(65001, ["10.0.0.0/8"], withdraw=True)
    assert "no network 10.0.0.0/8" in cmd
    assert "network 10.0.0.0/8" not in [x for x in cmd if not x.startswith("no")]


# --- load_config ---

def _write_config(data: dict) -> str:
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    yaml.dump(data, tmp)
    tmp.close()
    return tmp.name


def test_load_config_missing_file():
    with pytest.raises(ConfigError, match="not found"):
        load_config("/nonexistent/path/config.yaml")


def test_load_config_invalid_as():
    path = _write_config({
        "router": {
            "as_number": "not-an-int",
            "services": {"svc": {"as_numbers": [12345]}},
        }
    })
    try:
        with pytest.raises(ConfigError):
            load_config(path)
    finally:
        os.unlink(path)


def test_load_config_missing_services():
    path = _write_config({
        "router": {
            "as_number": 65001,
        }
    })
    try:
        with pytest.raises(ConfigError):
            load_config(path)
    finally:
        os.unlink(path)


def test_load_config_valid():
    path = _write_config({
        "router": {
            "as_number": 65001,
            "services": {"svc": {"as_numbers": [12345]}},
        }
    })
    try:
        cfg = load_config(path)
        assert cfg.as_number == 65001
        assert len(cfg.services) == 1
        assert cfg.services[0].name == "svc"
    finally:
        os.unlink(path)


# --- fetch_routes (unit, using semaphore parameter) ---

def test_fetch_routes_parses_routes(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        class R:
            stdout = "route: 10.0.0.0/8\n"
            stderr = ""
            returncode = 0
        return R()

    monkeypatch.setattr("getroutes.subprocess.run", fake_run)
    result = fetch_routes(12345, retries=1, retry_delay_sec=0, whois_timeout_sec=5)
    assert "10.0.0.0/8" in result
