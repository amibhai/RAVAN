"""Tests for the Lateral Movement head (Head #7) — credential reuse."""

from __future__ import annotations

from ravan.core.engine import Engine
from ravan.core.loader import StaticLoader
from ravan.core.sinks import ListSink
from ravan.heads.lateral_movement.head import LateralMovementHead
from ravan.schemas.events import Outcome

from conftest import IN_WINDOW, basic_auth_server, clock_at, make_scope


def _engine(scope, sink) -> Engine:
    loader = StaticLoader({"lateral": LateralMovementHead})
    return Engine(scope, sink=sink, loader=loader, clock=clock_at(IN_WINDOW))


def _scope(**over):
    base = {
        "targets": ["127.0.0.1"],
        "allowed_tactics": ["lateral-movement"],
        "permissions": ["lateral-movement"],
    }
    base.update(over)
    return make_scope(scope=base)


def test_lateral_reuse_grants_access() -> None:
    sink = ListSink()
    engine = _engine(_scope(), sink)
    with basic_auth_server("admin", "secret") as (_host, port):
        result = engine.run_head(
            "lateral",
            options={
                "protocols": ["http-basic"],
                "credentials": ["admin:secret"],
                "ports": {"http-basic": port},
                "timeout": 2.0,
            },
        )
    assert result.status == "ok"
    granted = [e for e in result.events if e.outcome is Outcome.SUCCESS]
    assert len(granted) == 1
    assert granted[0].attack_id == "T1021"
    assert granted[0].details["username"] == "admin"
    assert granted[0].details["enabled_by"] == "T1078"


def test_lateral_wrong_credentials_no_access() -> None:
    sink = ListSink()
    engine = _engine(_scope(), sink)
    with basic_auth_server("admin", "secret") as (_host, port):
        result = engine.run_head(
            "lateral",
            options={
                "protocols": ["http-basic"],
                "credentials": ["admin:wrong"],
                "ports": {"http-basic": port},
                "timeout": 2.0,
            },
        )
    assert result.status == "ok"
    assert not [e for e in result.events if e.outcome is Outcome.SUCCESS]
    assert result.report is not None
    assert "0 host/service" in result.report.summary


def test_lateral_ssh_uses_subtechnique() -> None:
    from ravan.heads.lateral_movement.head import LM_SUBTECH

    assert LM_SUBTECH["ssh"][0] == "T1021.004"


def test_lateral_requires_credentials() -> None:
    sink = ListSink()
    engine = _engine(_scope(), sink)
    result = engine.run_head("lateral", options={"protocols": ["http-basic"]})
    assert any(
        e.outcome is Outcome.FAIL and "credential" in e.details["reason"] for e in result.events
    )
