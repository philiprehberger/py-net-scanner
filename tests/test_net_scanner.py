"""Tests for philiprehberger_net_scanner."""

from __future__ import annotations

import socket
import threading
from contextlib import contextmanager
from typing import Iterator

import pytest

from philiprehberger_net_scanner import (
    COMMON_PORTS,
    Device,
    PortResult,
    is_port_open,
    scan_ports,
)


@contextmanager
def _tcp_server(host: str = "127.0.0.1") -> Iterator[int]:
    """Start a single-shot TCP server on an ephemeral port and yield the port."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, 0))
    server.listen(8)
    port = server.getsockname()[1]

    stop = threading.Event()

    def _accept_loop() -> None:
        server.settimeout(0.1)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.close()

    thread = threading.Thread(target=_accept_loop, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        thread.join(timeout=1.0)
        server.close()


def test_is_port_open_true_for_listening_socket() -> None:
    with _tcp_server() as port:
        assert is_port_open("127.0.0.1", port, timeout=2.0) is True


def test_is_port_open_false_for_closed_port() -> None:
    # Pick a port unlikely to be open.
    assert is_port_open("127.0.0.1", 1, timeout=0.5) is False


def test_is_port_open_false_for_unresolvable_host() -> None:
    assert is_port_open("not-a-real-host.invalid", 80, timeout=0.5) is False


def test_scan_ports_finds_listening_port() -> None:
    with _tcp_server() as port:
        results = scan_ports("127.0.0.1", ports=[port, 1], timeout=1.0)
    open_ports = [r.number for r in results]
    assert port in open_ports


def test_scan_ports_invalid_argument_raises() -> None:
    with pytest.raises(ValueError):
        scan_ports("127.0.0.1", ports=123)  # type: ignore[arg-type]


def test_scan_ports_unresolvable_host_raises() -> None:
    with pytest.raises(ValueError):
        scan_ports("not-a-real-host.invalid", ports=[80])


def test_device_str_format() -> None:
    d = Device(ip="10.0.0.1", hostname="server", response_time_ms=12.345)
    assert "10.0.0.1" in str(d)
    assert "server" in str(d)


def test_port_result_str_with_service() -> None:
    r = PortResult(number=80, state="open", service="http")
    assert "Port 80: open" in str(r)
    assert "http" in str(r)


def test_common_ports_includes_well_known() -> None:
    assert COMMON_PORTS[80] == "http"
    assert COMMON_PORTS[443] == "https"
    assert COMMON_PORTS[22] == "ssh"


def test_async_scan_ports_in_all() -> None:
    """Ensure async_scan_ports is exported."""
    import philiprehberger_net_scanner as mod

    assert "async_scan_ports" in mod.__all__
