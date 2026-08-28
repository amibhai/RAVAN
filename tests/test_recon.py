"""Tests for the Reconnaissance head (Head #1) and its scanning engine.

Network-dependent tests run against an ephemeral loopback listener, so they are
deterministic and need no external hosts or privileges.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from ravan.core.engine import Engine
from ravan.core.loader import StaticLoader
from ravan.core.sinks import ListSink
from ravan.heads.recon import cve
from ravan.heads.recon.head import ReconHead
from ravan.heads.recon.ports import classify_target, expand_hosts, parse_port_spec
from ravan.heads.recon.scanner import connect_scan, detect_service, scan_port

from conftest import IN_WINDOW, clock_at, make_scope


@contextmanager
def banner_server(banner: bytes) -> Iterator[tuple[str, int]]:
    """A loopback TCP server that announces ``banner`` on connect."""
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
                if banner:
                    conn.sendall(banner)
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


def _loader() -> StaticLoader:
    return StaticLoader({"recon": ReconHead})


# --- port / target parsing ----------------------------------------------------


def test_parse_port_spec() -> None:
    assert len(parse_port_spec("top20")) == 20
    assert len(parse_port_spec("top100")) == 100
    assert parse_port_spec("22,80,443") == [22, 80, 443]
    assert parse_port_spec("1-5") == [1, 2, 3, 4, 5]
    assert parse_port_spec(443) == [443]
    assert parse_port_spec("80,80,80") == [80]  # dedupe
    assert len(parse_port_spec("all")) == 65535


def test_classify_and_expand() -> None:
    assert classify_target("10.0.0.0/24") == "cidr"
    assert classify_target("10.0.0.5") == "ip"
    assert classify_target("lab.local") == "host"
    assert expand_hosts("192.168.56.0/30") == ["192.168.56.1", "192.168.56.2"]
    assert expand_hosts("10.0.0.0/8", max_hosts=5) == [
        "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5",
    ]


# --- CVE database -------------------------------------------------------------


def test_cve_db_loads_and_all_regexes_valid() -> None:
    entries = cve.load_cve_db()
    assert len(entries) == 55  # all entries have a compilable regex
    for entry in entries:
        assert entry.pattern() is not None


def test_match_cves_against_apache_banner() -> None:
    matches = cve.match_cves("HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n")
    ids = {m.cve_id for m in matches}
    assert "CVE-2021-41773" in ids
    assert cve.match_cves("") == []
    # results are sorted highest-CVSS first
    scores = [m.cvss_score for m in matches]
    assert scores == sorted(scores, reverse=True)


# --- scanning -----------------------------------------------------------------


def test_scan_port_open_and_closed() -> None:
    with banner_server(b"") as (host, port):
        assert scan_port(host, port, timeout=2.0) == "open"
    # after the server closes, the port is no longer open
    assert scan_port(host, port, timeout=1.0) != "open"


def test_connect_scan_finds_open_port() -> None:
    with banner_server(b"") as (host, port):
        results = connect_scan(host, [port, port + 1], timeout=2.0, workers=4)
    open_ports = {r.port for r in results}
    assert port in open_ports


def test_detect_service_identifies_ssh() -> None:
    with banner_server(b"SSH-2.0-OpenSSH_8.9p1\r\n") as (host, port):
        service, version, banner = detect_service(host, port, timeout=2.0)
    assert service == "ssh"
    assert "OpenSSH_8.9" in version or "SSH-2.0" in banner


# --- end-to-end via engine ----------------------------------------------------


def test_recon_end_to_end_emits_attack_tagged_events() -> None:
    scope = make_scope(scope={"targets": ["127.0.0.1"]})
    sink = ListSink()
    engine = Engine(scope, sink=sink, loader=_loader(), clock=clock_at(IN_WINDOW))
    with banner_server(b"220 ProFTPD 1.3.5 Server ready\r\n") as (_host, port):
        result = engine.run_head(
            "recon",
            options={"operations": ["portscan", "services"], "ports": str(port), "timeout": 2.0},
        )
    assert result.status == "ok"
    by_technique = {e.attack_id for e in result.events}
    assert "T1595.001" in by_technique  # port scan
    assert "T1592.002" in by_technique  # service identification
    svc_events = [e for e in result.events if e.attack_id == "T1592.002"]
    assert svc_events[0].details.get("service") == "ftp"
    assert result.report is not None
    assert result.report.total_events == len(result.events)


def test_recon_reports_no_open_ports_cleanly() -> None:
    # A closed port yields a clean portscan event with an empty open-port list.
    scope = make_scope(scope={"targets": ["127.0.0.1"]})
    engine = Engine(scope, sink=ListSink(), loader=_loader(), clock=clock_at(IN_WINDOW))
    with banner_server(b"") as (_host, port):
        closed_port = port  # captured; server closes on context exit
    result = engine.run_head(
        "recon",
        options={"operations": ["portscan"], "ports": str(closed_port), "timeout": 1.0},
    )
    assert result.status == "ok"
    portscan = [e for e in result.events if e.attack_id == "T1595.001"]
    assert portscan and portscan[0].details["open_ports"] == []


@pytest.mark.parametrize("spec", ["top20", "22,80"])
def test_recon_accepts_port_specs(spec: str) -> None:
    scope = make_scope(scope={"targets": ["127.0.0.1"]})
    engine = Engine(scope, sink=ListSink(), loader=_loader(), clock=clock_at(IN_WINDOW))
    result = engine.run_head(
        "recon", options={"operations": ["portscan"], "ports": spec, "timeout": 0.5}
    )
    assert result.status == "ok"
