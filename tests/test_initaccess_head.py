"""Tests for the Initial Access head (Head #3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ravan.core.engine import Engine
from ravan.core.exceptions import ScopeViolation
from ravan.core.loader import StaticLoader
from ravan.core.sinks import ListSink
from ravan.heads.initial_access.head import InitialAccessHead
from ravan.schemas.events import Outcome

from conftest import IN_WINDOW, basic_auth_server, clock_at, make_scope


def _engine(scope, sink) -> Engine:
    return Engine(
        scope,
        sink=sink,
        loader=StaticLoader({"initaccess": InitialAccessHead}),
        clock=clock_at(IN_WINDOW),
    )


def _scope(**over):
    base = {
        "targets": ["127.0.0.1"],
        "allowed_tactics": ["initial-access"],
        "permissions": ["initial-access"],
    }
    base.update(over)
    return make_scope(scope=base)


def test_initaccess_generates_benign_lures(tmp_path: Path) -> None:
    result = _engine(_scope(), ListSink()).run_head(
        "initaccess",
        options={"operations": ["phishing-lure"], "output_dir": str(tmp_path)},
    )
    assert result.status == "ok"
    lures = [e for e in result.events if e.attack_id.startswith("T1566")]
    assert len(lures) == 4
    assert {e.attack_id for e in lures} == {"T1566.001", "T1566.002"}
    files = list(tmp_path.glob("lure_*"))
    assert len(files) == 4
    # content is benign and marker-tagged
    assert any("RAVAN-BENIGN" in f.read_text(encoding="utf-8") for f in files)


def test_initaccess_valid_account_foothold() -> None:
    with basic_auth_server("admin", "secret") as (_host, port):
        result = _engine(_scope(), ListSink()).run_head(
            "initaccess",
            options={
                "operations": ["valid-accounts"],
                "protocol": "http-basic",
                "port": port,
                "credentials": ["admin:secret"],
                "timeout": 2.0,
            },
        )
    footholds = [e for e in result.events if e.attack_id == "T1078"]
    assert len(footholds) == 1
    assert footholds[0].outcome is Outcome.SUCCESS
    assert footholds[0].details["username"] == "admin"


def test_initaccess_wrong_credentials_no_foothold() -> None:
    with basic_auth_server("admin", "secret") as (_host, port):
        result = _engine(_scope(), ListSink()).run_head(
            "initaccess",
            options={
                "operations": ["valid-accounts"],
                "protocol": "http-basic",
                "port": port,
                "credentials": ["admin:wrong"],
                "timeout": 2.0,
            },
        )
    assert not any(e.attack_id == "T1078" for e in result.events)


def test_initaccess_requires_permission() -> None:
    scope = _scope(permissions=["active-scan"])  # missing initial-access
    with pytest.raises(ScopeViolation):
        _engine(scope, ListSink()).run_head("initaccess", options={"operations": ["phishing-lure"]})
