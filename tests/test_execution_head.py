"""Tests for the Execution head (Head #4)."""

from __future__ import annotations

import pytest

from ravan.core.engine import Engine
from ravan.core.exceptions import ScopeViolation
from ravan.core.loader import StaticLoader
from ravan.core.sinks import ListSink
from ravan.emulation.system import Platform, current_platform
from ravan.heads.execution.atomics import PowerShellExec, PythonExec, ShellExec
from ravan.heads.execution.head import ExecutionHead
from ravan.schemas.events import Outcome

from conftest import IN_WINDOW, clock_at, make_scope


def _engine(scope, sink) -> Engine:
    return Engine(
        scope,
        sink=sink,
        loader=StaticLoader({"execution": ExecutionHead}),
        clock=clock_at(IN_WINDOW),
    )


def _scope(**over):
    base = {
        "targets": ["127.0.0.1", "localhost"],
        "allowed_tactics": ["execution"],
        "permissions": ["execute-emulation"],
    }
    base.update(over)
    return make_scope(scope=base)


def test_execution_python_atomic_runs() -> None:
    sink = ListSink()
    engine = _engine(_scope(), sink)
    result = engine.run_head("execution", options={"atomics": ["python"]})
    assert result.status == "ok"
    events = [e for e in result.events if e.outcome is Outcome.SUCCESS]
    assert len(events) == 1
    assert events[0].attack_id == "T1059.006"
    assert events[0].details["marker_echoed"] is True
    assert events[0].details["pid"] is not None


def test_execution_requires_local_authorization() -> None:
    # localhost / 127.0.0.1 / hostname not in scope -> refused, nothing executed
    scope = _scope(targets=["10.10.0.0/24"])
    sink = ListSink()
    result = _engine(scope, sink).run_head("execution", options={"atomics": ["python"]})
    assert result.status == "ok"
    assert any(e.outcome is Outcome.BLOCKED for e in result.events)
    # nothing was executed — the only event is the refusal
    assert not any(e.outcome is Outcome.SUCCESS for e in result.events)


def test_execution_requires_permission() -> None:
    scope = _scope(permissions=["active-scan"])  # missing execute-emulation
    with pytest.raises(ScopeViolation):
        _engine(scope, ListSink()).run_head("execution", options={"atomics": ["python"]})


def test_atomic_platform_applicability() -> None:
    assert PythonExec().applicable()  # every platform
    assert PowerShellExec().applicable() == (current_platform() is Platform.WINDOWS)
    assert ShellExec().applicable() == (current_platform() in (Platform.LINUX, Platform.DARWIN))
