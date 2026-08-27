"""Tests for the engine: scope enforcement, dispatch, and plugin isolation.

These are the tests that prove authorized-use enforcement is structural — an
in-scope action succeeds, and every out-of-scope action is refused *and logged*
by the engine, not by the head.
"""

from __future__ import annotations

import pytest

from ravan.core.base import BaseHead, RunContext
from ravan.core.engine import Engine
from ravan.core.exceptions import HeadNotFound, ScopeViolation
from ravan.core.loader import StaticLoader
from ravan.core.sinks import ListSink
from ravan.heads.recon.head import ReconHead
from ravan.schemas.events import HeadReport, Outcome, Tactic

from conftest import AFTER_WINDOW, IN_WINDOW, clock_at, make_scope

# --- test-only heads (module 'test_engine', so the real loader ignores them) ---


class CrashHead(BaseHead):
    head_name = "crash"
    technique_id = "T1595"
    technique_name = "Active Scanning"
    tactic = Tactic.RECONNAISSANCE
    required_permissions = ("active-scan",)

    def run(self, context: RunContext) -> None:
        raise RuntimeError("simulated head crash")

    def report(self) -> HeadReport:
        return self.build_report("crashed")

    def cleanup(self) -> None:
        pass


class OutOfScopeTargetHead(BaseHead):
    head_name = "oos"
    technique_id = "T1595"
    technique_name = "Active Scanning"
    tactic = Tactic.RECONNAISSANCE
    required_permissions = ("active-scan",)

    def run(self, context: RunContext) -> None:
        context.authorize("203.0.113.9")  # deliberately out of scope

    def report(self) -> HeadReport:
        return self.build_report("attempted out-of-scope action")

    def cleanup(self) -> None:
        pass


def _engine(scope, sink: ListSink, heads=None, clock=None) -> Engine:
    loader = StaticLoader(heads or {"recon": ReconHead})
    return Engine(scope, sink=sink, loader=loader, clock=clock or clock_at(IN_WINDOW))


# --- happy path ---------------------------------------------------------------


def test_in_scope_run_succeeds() -> None:
    sink = ListSink()
    engine = _engine(make_scope(), sink)
    result = engine.run_head("recon")

    assert result.status == "ok"
    assert len(result.events) == 2  # one per in-scope target
    assert all(e.outcome is Outcome.SUCCESS for e in result.events)
    assert {e.target for e in result.events} == {"10.10.0.0/24", "lab.local"}
    # events reached the sink too
    assert len(sink.events) == 2
    assert result.report is not None
    assert result.report.successes == 2


def test_report_runs_before_cleanup() -> None:
    # recon builds its summary from state that cleanup() clears, so a summary
    # that still names the processed targets proves report() ran first.
    sink = ListSink()
    engine = _engine(make_scope(), sink)
    result = engine.run_head("recon")

    assert result.report is not None
    assert "processed 2" in result.report.summary
    assert "lab.local" in result.report.summary


# --- whole-head scope refusals (engine-side preflight, must raise) ------------


def test_out_of_scope_tactic_is_refused() -> None:
    sink = ListSink()
    scope = make_scope(scope={"allowed_tactics": ["execution"]})
    engine = _engine(scope, sink)

    with pytest.raises(ScopeViolation):
        engine.run_head("recon")

    # The refusal was logged as a BLOCKED event.
    assert len(sink.events) == 1
    assert sink.events[0].outcome is Outcome.BLOCKED
    assert "tactic" in sink.events[0].details["reason"]


def test_missing_permission_is_refused() -> None:
    sink = ListSink()
    scope = make_scope(scope={"permissions": ["wordlist-generation"]})  # no active-scan
    engine = _engine(scope, sink)

    with pytest.raises(ScopeViolation):
        engine.run_head("recon")

    assert sink.events[-1].outcome is Outcome.BLOCKED
    assert "permission" in sink.events[-1].details["reason"]


def test_action_outside_time_window_is_refused() -> None:
    sink = ListSink()
    engine = _engine(make_scope(), sink, clock=clock_at(AFTER_WINDOW))

    with pytest.raises(ScopeViolation):
        engine.run_head("recon")

    assert sink.events[-1].outcome is Outcome.BLOCKED
    assert "time window" in sink.events[-1].details["reason"]


def test_disallowed_technique_is_refused() -> None:
    sink = ListSink()
    scope = make_scope(scope={"allowed_techniques": ["T1110"]})  # recon is T1595
    engine = _engine(scope, sink)

    with pytest.raises(ScopeViolation):
        engine.run_head("recon")

    assert sink.events[-1].outcome is Outcome.BLOCKED


# --- per-target refusal (logged, non-fatal, does not raise out of run_head) ---


def test_out_of_scope_target_is_blocked_and_logged() -> None:
    sink = ListSink()
    engine = _engine(make_scope(), sink, heads={"oos": OutOfScopeTargetHead})
    result = engine.run_head("oos")

    assert result.status == "scope-violation"
    assert len(result.events) == 1
    assert result.events[0].outcome is Outcome.BLOCKED
    assert result.events[0].target == "203.0.113.9"


# --- unknown head -------------------------------------------------------------


def test_unknown_head_raises() -> None:
    engine = _engine(make_scope(), ListSink())
    with pytest.raises(HeadNotFound):
        engine.run_head("nonexistent")


# --- plugin isolation ---------------------------------------------------------


def test_head_crash_is_isolated() -> None:
    sink = ListSink()
    engine = _engine(make_scope(), sink, heads={"crash": CrashHead})
    result = engine.run_head("crash")  # must not raise

    assert result.status == "error"
    fail_events = [e for e in result.events if e.outcome is Outcome.FAIL]
    assert len(fail_events) == 1
    assert "traceback" in fail_events[0].details
