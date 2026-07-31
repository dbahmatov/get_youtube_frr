"""Тесты сопоставления IP → ASN через Team Cymru.

Фикстура `cymru_bulk.txt` — настоящий ответ сервиса, снятый 2026-07-30, со
всеми его особенностями: сбитым выравниванием на длинных v6-адресах и `NA`
вместо ASN у немаршрутизируемого адреса.

Bulk-режим выбран не ради скорости, а ради вежливости: сотни адресов уходят
одним соединением вместо сотни отдельных запросов к бесплатному сервису.
"""

import os
import socket
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from bgpfeed.asnmap import cymru
from bgpfeed.errors import FetchError

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

with open(os.path.join(FIXTURES, "cymru_bulk.txt"), encoding="utf-8") as _handle:
    BULK_RESPONSE = _handle.read()


class FakeSocket:
    """Подменяет соединение с whois.cymru.com."""

    def __init__(self, response: str, fail: Exception = None):
        self.response = response.encode()
        self.fail = fail
        self.sent = b""
        self.closed = False
        self._offset = 0

    def sendall(self, data):
        if self.fail is not None:
            raise self.fail
        self.sent += data

    def recv(self, size):
        chunk = self.response[self._offset:self._offset + size]
        self._offset += len(chunk)
        return chunk

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


@pytest.fixture
def fake_connect(monkeypatch):
    created = []

    def factory(response=BULK_RESPONSE, fail=None, connect_error=None):
        def connect(address, timeout=None):
            if connect_error is not None:
                raise connect_error
            sock = FakeSocket(response, fail)
            created.append(sock)
            return sock

        monkeypatch.setattr(socket, "create_connection", connect)
        return created

    return factory


# --- парсер ---

def test_parses_asn_per_ip():
    result = cymru.parse_bulk_response(BULK_RESPONSE)
    assert result["8.8.8.8"].asn == 15169
    assert result["142.250.185.78"].asn == 15169


def test_parses_ipv6():
    """У длинных v6-адресов Cymru ломает выравнивание колонок."""
    result = cymru.parse_bulk_response(BULK_RESPONSE)
    assert result["2001:4860:4860::8888"].asn == 15169


def test_parses_bgp_prefix():
    """Покрывающий префикс приходит вместе с ASN — RADB для него не нужен."""
    result = cymru.parse_bulk_response(BULK_RESPONSE)
    assert str(result["8.8.8.8"].prefix) == "8.8.8.0/24"
    assert str(result["2001:4860:4860::8888"].prefix) == "2001:4860::/32"


def test_unrouted_address_has_no_asn():
    """`NA` означает «адрес никем не анонсируется» — это не ошибка разбора."""
    result = cymru.parse_bulk_response(BULK_RESPONSE)
    assert result["1.2.3.4"].asn is None
    assert result["1.2.3.4"].prefix is None


def test_header_line_ignored():
    result = cymru.parse_bulk_response(BULK_RESPONSE)
    assert "Bulk mode; whois.cymru.com" not in result


def test_as_name_captured():
    result = cymru.parse_bulk_response(BULK_RESPONSE)
    assert "Google" in result["8.8.8.8"].as_name


def test_empty_response_parses_to_nothing():
    assert cymru.parse_bulk_response("") == {}


def test_garbage_lines_skipped():
    text = "Bulk mode\nnot a valid line\n15169 | 8.8.8.8 | 8.8.8.0/24 | US | arin | x | GOOGLE\n"
    result = cymru.parse_bulk_response(text)
    assert set(result) == {"8.8.8.8"}


# --- bulk-запрос ---

def test_single_connection_for_many_ips(fake_connect):
    created = fake_connect()
    cymru.lookup(["8.8.8.8", "142.250.185.78", "2001:4860:4860::8888", "1.2.3.4"])
    assert len(created) == 1, "все адреса обязаны уходить одним соединением"


def test_query_uses_begin_verbose_end(fake_connect):
    created = fake_connect()
    cymru.lookup(["8.8.8.8"])
    sent = created[0].sent.decode()
    assert sent.startswith("begin\n")
    assert "verbose\n" in sent
    assert sent.rstrip().endswith("end")


def test_all_ips_included_in_query(fake_connect):
    created = fake_connect()
    cymru.lookup(["8.8.8.8", "1.2.3.4"])
    sent = created[0].sent.decode()
    assert "8.8.8.8" in sent and "1.2.3.4" in sent


def test_lookup_returns_mapping(fake_connect):
    fake_connect()
    result = cymru.lookup(["8.8.8.8"])
    assert result["8.8.8.8"].asn == 15169


def test_unanswered_ip_marked_none(fake_connect):
    """Адрес, о котором Cymru промолчал, обязан присутствовать в ответе."""
    fake_connect()
    result = cymru.lookup(["8.8.8.8", "9.9.9.9"])
    assert "9.9.9.9" in result
    assert result["9.9.9.9"].asn is None


def test_empty_input_makes_no_connection(fake_connect):
    created = fake_connect()
    assert cymru.lookup([]) == {}
    assert created == []


def test_socket_closed_after_use(fake_connect):
    created = fake_connect()
    cymru.lookup(["8.8.8.8"])
    assert created[0].closed


def test_batches_large_input(fake_connect):
    """Очень длинный список режется на несколько соединений, а не одно гигантское."""
    created = fake_connect()
    cymru.lookup([f"10.0.{i // 256}.{i % 256}" for i in range(2500)], batch_size=1000)
    assert len(created) == 3


# --- сбои ---

def test_connection_failure_raises(fake_connect):
    fake_connect(connect_error=OSError("connection refused"))
    with pytest.raises(FetchError, match="cymru"):
        cymru.lookup(["8.8.8.8"])


def test_timeout_raises(fake_connect):
    fake_connect(connect_error=socket.timeout("timed out"))
    with pytest.raises(FetchError, match="timeout"):
        cymru.lookup(["8.8.8.8"])


def test_send_failure_raises(fake_connect):
    fake_connect(fail=OSError("broken pipe"))
    with pytest.raises(FetchError):
        cymru.lookup(["8.8.8.8"])


def test_failure_is_not_an_empty_mapping(fake_connect):
    """Недоступность Cymru не должна выглядеть как «ни один IP никому не принадлежит»."""
    fake_connect(connect_error=OSError("down"))
    with pytest.raises(FetchError):
        cymru.lookup(["8.8.8.8"])
