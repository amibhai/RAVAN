"""RAVAN core engine: plugin contract, scope enforcement, and dispatch."""

from __future__ import annotations

from ravan.core.base import BaseHead, RunContext
from ravan.core.engine import Engine, RunResult
from ravan.core.exceptions import (
    DuplicateHeadError,
    HeadLoadError,
    HeadNotFound,
    RavanError,
    ScopeConfigError,
    ScopeViolation,
)
from ravan.core.loader import HeadLoader, Loader, StaticLoader
from ravan.core.scope import EngagementScope, normalize_tactic
from ravan.core.sinks import (
    ConsoleSink,
    EventSink,
    JsonlFileSink,
    ListSink,
    MultiSink,
)

__all__ = [
    "BaseHead",
    "ConsoleSink",
    "DuplicateHeadError",
    "EngagementScope",
    "Engine",
    "EventSink",
    "HeadLoadError",
    "HeadLoader",
    "HeadNotFound",
    "JsonlFileSink",
    "ListSink",
    "Loader",
    "MultiSink",
    "RavanError",
    "RunContext",
    "RunResult",
    "ScopeConfigError",
    "ScopeViolation",
    "StaticLoader",
    "normalize_tactic",
]
