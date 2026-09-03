"""Shared lab-safe emulation library used by the execution, persistence, and
initial-access heads: OS detection, a no-shell benign command runner, canary
markers, and the atomic interface."""

from __future__ import annotations

from ravan.emulation.atomic import (
    Atomic,
    AtomicOutcome,
    AtomicStatus,
    resolve_local_target,
)
from ravan.emulation.runner import (
    AtomicEnv,
    CommandResult,
    marker,
    run_command,
    staging_dir,
)
from ravan.emulation.system import Platform, current_platform, is_windows, which

__all__ = [
    "Atomic",
    "AtomicEnv",
    "AtomicOutcome",
    "AtomicStatus",
    "CommandResult",
    "Platform",
    "current_platform",
    "is_windows",
    "marker",
    "resolve_local_target",
    "run_command",
    "staging_dir",
    "which",
]
