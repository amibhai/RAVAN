"""Shared test fixtures and helpers."""

from __future__ import annotations

import base64
import http.server
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

import pytest

from ravan.core.scope import EngagementScope
from ravan.core.sinks import ListSink

# A moment that sits inside the default test engagement window.
IN_WINDOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
# A moment after the default window's end.
AFTER_WINDOW = datetime(2027, 6, 1, 12, 0, tzinfo=UTC)


def make_scope(**overrides: Any) -> EngagementScope:
    """Build a valid default scope, with optional per-field overrides.

    Pass ``scope={...}`` to override keys inside the ``scope`` block.
    """
    scope_block: dict[str, Any] = {
        "targets": ["10.10.0.0/24", "lab.local"],
        "allowed_tactics": ["reconnaissance", "resource-development"],
        "allowed_techniques": [],
        "permissions": ["active-scan", "wordlist-generation"],
        "time_window": {"start": "2026-01-01T00:00:00Z", "end": "2027-01-01T00:00:00Z"},
    }
    scope_block.update(overrides.pop("scope", {}))
    data: dict[str, Any] = {"name": "test-engagement", "scope": scope_block}
    data.update(overrides)
    return EngagementScope.from_mapping(data)


def clock_at(moment: datetime) -> Any:
    return lambda: moment


@pytest.fixture
def scope() -> EngagementScope:
    return make_scope()


@pytest.fixture
def sink() -> ListSink:
    return ListSink()


# --- local test servers (loopback, ephemeral port) ---------------------------


@contextmanager
def basic_auth_server(
    username: str, password: str, *, server_header: str = "LabApp/1.0"
) -> Iterator[tuple[str, int]]:
    """An HTTP server on 127.0.0.1 that returns 200 only for the given Basic
    credentials, else 401."""
    expected = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.headers.get("Authorization") == expected:
                self.send_response(200)
                self.send_header("Server", server_header)
                self.end_headers()
                self.wfile.write(b"ok")
            else:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="x"')
                self.end_headers()
                self.wfile.write(b"denied")

        def log_message(self, *args: Any) -> None:
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield "127.0.0.1", port
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=2)


@contextmanager
def redis_like_server(password: str) -> Iterator[tuple[str, int]]:
    """A minimal RESP server on 127.0.0.1 answering the AUTH command: +OK for
    the right password, -WRONGPASS otherwise, or the 'no password set' error
    when configured with an empty password."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        srv.settimeout(0.3)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                data = conn.recv(1024).decode("latin-1", "replace")
                tokens = [t for t in data.split("\r\n") if t and not t.startswith(("*", "$"))]
                supplied = tokens[-1] if tokens else ""
                if not password:
                    conn.sendall(b"-ERR Client sent AUTH, but no password is set\r\n")
                elif supplied == password:
                    conn.sendall(b"+OK\r\n")
                else:
                    conn.sendall(b"-WRONGPASS invalid password\r\n")
            except OSError:
                pass
            finally:
                conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield "127.0.0.1", port
    finally:
        stop.set()
        srv.close()
        thread.join(timeout=2)
