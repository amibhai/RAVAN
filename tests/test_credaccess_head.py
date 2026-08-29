"""Tests for the Credential Access head (Head #6)."""

from __future__ import annotations

import pytest

from ravan.core.engine import Engine
from ravan.core.exceptions import ScopeViolation
from ravan.core.loader import StaticLoader
from ravan.core.sinks import ListSink
from ravan.heads.credential_access.head import CredentialAccessHead
from ravan.schemas.events import Outcome

from conftest import IN_WINDOW, basic_auth_server, clock_at, make_scope


def _engine(scope, sink) -> Engine:
    loader = StaticLoader({"credaccess": CredentialAccessHead})
    return Engine(scope, sink=sink, loader=loader, clock=clock_at(IN_WINDOW))


def _scope(**over):
    base = {
        "targets": ["127.0.0.1"],
        "allowed_tactics": ["credential-access"],
        "permissions": ["credential-attack"],
    }
    base.update(over)
    return make_scope(scope=base)


def test_credaccess_finds_credential() -> None:
    sink = ListSink()
    engine = _engine(_scope(), sink)
    with basic_auth_server("admin", "secret") as (_host, port):
        result = engine.run_head(
            "credaccess",
            options={
                "protocol": "http-basic",
                "port": port,
                "mode": "dictionary",
                "users": ["admin"],
                "passwords": ["wrong", "secret"],
                "timeout": 2.0,
                "workers": 1,
            },
        )
    assert result.status == "ok"
    found = [e for e in result.events if e.outcome is Outcome.SUCCESS]
    assert len(found) == 1
    assert found[0].attack_id == "T1110.001"
    assert found[0].details["username"] == "admin"
    assert found[0].details["password"] == "secret"


def test_credaccess_spray_tags_password_spraying() -> None:
    sink = ListSink()
    engine = _engine(_scope(), sink)
    with basic_auth_server("admin", "secret") as (_host, port):
        result = engine.run_head(
            "credaccess",
            options={
                "protocol": "http-basic",
                "port": port,
                "mode": "spray",
                "users": ["admin", "root"],
                "passwords": ["secret"],
                "timeout": 2.0,
                "workers": 1,
            },
        )
    found = [e for e in result.events if e.outcome is Outcome.SUCCESS]
    assert found and found[0].attack_id == "T1110.003"  # spray


def test_credaccess_documents_failed_campaign() -> None:
    sink = ListSink()
    engine = _engine(_scope(), sink)
    with basic_auth_server("admin", "secret") as (_host, port):
        result = engine.run_head(
            "credaccess",
            options={
                "protocol": "http-basic",
                "port": port,
                "mode": "dictionary",
                "users": ["admin"],
                "passwords": ["a", "b", "c"],
                "timeout": 2.0,
                "workers": 1,
            },
        )
    # no success, but the brute campaign is still logged for detection validation
    assert not [e for e in result.events if e.outcome is Outcome.SUCCESS]
    fails = [e for e in result.events if e.outcome is Outcome.FAIL]
    assert fails and fails[0].details["attempts"] == 3


def test_credaccess_unknown_protocol_fails_cleanly() -> None:
    sink = ListSink()
    engine = _engine(_scope(), sink)
    result = engine.run_head("credaccess", options={"protocol": "bogus"})
    assert result.status == "ok"  # head ran, reported the misconfig
    assert any(
        e.outcome is Outcome.FAIL and "protocol" in e.details["reason"] for e in result.events
    )


def test_credaccess_requires_permission() -> None:
    scope = _scope(permissions=["active-scan"])  # missing credential-attack
    engine = _engine(scope, ListSink())
    with pytest.raises(ScopeViolation):
        engine.run_head("credaccess", options={"protocol": "ftp"})
