"""Shared test fixtures and helpers."""

from __future__ import annotations

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
