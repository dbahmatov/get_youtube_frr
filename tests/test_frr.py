"""Тесты работы с FRR через vtysh.

Проверяется в первую очередь то, что старый код делал неверно или не делал
вовсе: IPv6 требует своей address-family (иначе `network 2001:...` просто не
применится), а провалившийся батч обязан ронять запуск, а не логироваться и
списываться в «announced successfully».
"""

import ipaddress
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from bgpfeed import frr
from bgpfeed.errors import AnnouncementError


def nets(*cidrs):
    return [ipaddress.ip_network(c) for c in cidrs]


class FakeRun:
    def __init__(self, returncode=0, stdout="", stderr="", exc=None):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.exc = exc
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if self.exc is not None:
            raise self.exc
        return subprocess.CompletedProcess(args, self.returncode, self.stdout, self.stderr)

    @property
    def scripts(self):
        """Тексты конфигурации, поданные в vtysh -c."""
        return [args[args.index("-c") + 1] for args, _ in self.calls]


RUNNING_CONFIG = """
router bgp 65003
 address-family ipv4 unicast
  network 1.1.1.0/24
 exit-address-family
exit
!
router bgp 65004
 bgp router-id 10.0.0.21
 address-family ipv4 unicast
  network 8.8.8.0/24
  network 8.8.4.0/24 route-map IMPORTED
 exit-address-family
 address-family ipv6 unicast
  network 2001:4860::/32
 exit-address-family
exit
!
ip route 9.9.9.0/24 192.0.2.1
"""


# --- формирование конфигурации ---

def test_ipv4_network_statements():
    script = frr.build_script(65001, nets("8.8.8.0/24", "1.1.1.0/24"), announce=True)
    assert "router bgp 65001" in script
    assert "network 1.1.1.0/24" in script
    assert "network 8.8.8.0/24" in script


def test_withdraw_uses_no_network():
    script = frr.build_script(65001, nets("8.8.8.0/24"), announce=False)
    assert "no network 8.8.8.0/24" in script


def test_ipv6_wrapped_in_address_family():
    """Без `address-family ipv6 unicast` анонс v6 молча не применяется."""
    script = frr.build_script(65001, nets("2001:4860::/32"), announce=True)
    lines = [line.strip() for line in script.splitlines()]
    family = lines.index("address-family ipv6 unicast")
    assert lines.index("network 2001:4860::/32") > family
    assert "exit-address-family" in lines


def test_ipv4_not_wrapped_in_ipv6_family():
    script = frr.build_script(65001, nets("8.8.8.0/24"), announce=True)
    assert "address-family ipv6 unicast" not in script


def test_mixed_families_both_present():
    script = frr.build_script(65001, nets("8.8.8.0/24", "2001:4860::/32"), announce=True)
    lines = [line.strip() for line in script.splitlines()]
    assert lines.index("network 8.8.8.0/24") < lines.index("address-family ipv6 unicast")
    assert "network 2001:4860::/32" in lines


def test_script_starts_in_configure_mode():
    lines = [l.strip() for l in frr.build_script(65001, nets("8.8.8.0/24"), announce=True).splitlines()]
    assert lines[0] == "configure terminal"


# --- чтение текущей конфигурации и diff ---

def test_parse_configured_networks_is_scoped_to_local_as():
    assert frr.parse_configured_networks(RUNNING_CONFIG, 65004) == nets(
        "8.8.4.0/24", "8.8.8.0/24", "2001:4860::/32",
    )


def test_parse_configured_networks_rejects_missing_router_section():
    with pytest.raises(AnnouncementError, match="AS65005"):
        frr.parse_configured_networks(RUNNING_CONFIG, 65005)


def test_reconciliation_diff_is_sorted_and_disjoint():
    plan = frr.reconciliation_diff(
        current=nets("8.8.8.0/24", "1.1.1.0/24"),
        desired=nets("8.8.8.0/24", "9.9.9.0/24"),
    )
    assert plan.to_add == nets("9.9.9.0/24")
    assert plan.to_remove == nets("1.1.1.0/24")


def test_get_configured_networks_uses_read_only_vtysh(monkeypatch):
    fake = FakeRun(stdout=RUNNING_CONFIG)
    monkeypatch.setattr(subprocess, "run", fake)

    assert frr.get_configured_networks(65004) == nets(
        "8.8.4.0/24", "8.8.8.0/24", "2001:4860::/32",
    )
    args, kwargs = fake.calls[0]
    assert args == ["vtysh", "-c", "show running-config"]
    assert kwargs.get("shell") in (None, False)


def test_get_configured_networks_failure_is_not_an_empty_set(monkeypatch):
    fake = FakeRun(returncode=1, stderr="vtysh unavailable")
    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(AnnouncementError, match="running config"):
        frr.get_configured_networks(65004)


# --- применение ---

def test_apply_calls_vtysh(monkeypatch):
    fake = FakeRun()
    monkeypatch.setattr(subprocess, "run", fake)
    frr.announce(65001, nets("8.8.8.0/24"))

    args, kwargs = fake.calls[0]
    assert args[0] == "vtysh"
    assert kwargs.get("shell") in (None, False)


def test_apply_batches_large_sets(monkeypatch):
    fake = FakeRun()
    monkeypatch.setattr(subprocess, "run", fake)
    many = nets(*[f"8.{i // 256}.{i % 256}.0/24" for i in range(2500)])
    frr.announce(65001, many, batch_size=1000)
    assert len(fake.calls) == 3


def test_every_batch_reopens_router_context(monkeypatch):
    """Каждый вызов vtysh — отдельная сессия, контекст не переносится."""
    fake = FakeRun()
    monkeypatch.setattr(subprocess, "run", fake)
    many = nets(*[f"8.{i // 256}.{i % 256}.0/24" for i in range(1500)])
    frr.announce(65001, many, batch_size=1000)
    assert all("router bgp 65001" in script for script in fake.scripts)


def test_failed_batch_raises(monkeypatch):
    """Старый код логировал провал и рапортовал об успехе. Больше нет."""
    fake = FakeRun(returncode=1, stderr="% Unknown command")
    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(AnnouncementError, match="vtysh"):
        frr.announce(65001, nets("8.8.8.0/24"))


def test_timeout_raises(monkeypatch):
    fake = FakeRun(exc=subprocess.TimeoutExpired(cmd=["vtysh"], timeout=120))
    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(AnnouncementError, match="timeout"):
        frr.announce(65001, nets("8.8.8.0/24"))


def test_missing_vtysh_raises(monkeypatch):
    fake = FakeRun(exc=FileNotFoundError("vtysh"))
    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(AnnouncementError, match="vtysh"):
        frr.announce(65001, nets("8.8.8.0/24"))


def test_dry_run_does_not_call_vtysh(monkeypatch):
    fake = FakeRun()
    monkeypatch.setattr(subprocess, "run", fake)
    scripts = frr.announce(65001, nets("8.8.8.0/24"), dry_run=True)
    assert fake.calls == []
    assert "network 8.8.8.0/24" in scripts[0]


def test_empty_prefix_set_is_a_noop(monkeypatch):
    fake = FakeRun()
    monkeypatch.setattr(subprocess, "run", fake)
    assert frr.announce(65001, []) == []
    assert fake.calls == []


def test_withdraw_calls_vtysh_with_no_network(monkeypatch):
    fake = FakeRun()
    monkeypatch.setattr(subprocess, "run", fake)
    frr.withdraw(65001, nets("8.8.8.0/24"))
    assert "no network 8.8.8.0/24" in fake.scripts[0]
