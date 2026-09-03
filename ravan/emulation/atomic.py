"""The atomic interface shared by the emulation heads.

An *atomic* is one lab-safe emulation of a single ATT&CK (sub-)technique. It
declares which platforms it runs on, executes a benign action that generates
realistic telemetry, and (for stateful techniques like persistence) reverts
itself idempotently.
"""

from __future__ import annotations

import abc
import socket
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, ClassVar

from ravan.core.scope import EngagementScope
from ravan.emulation.runner import AtomicEnv
from ravan.emulation.system import Platform, current_platform


class AtomicStatus(StrEnum):
    SUCCESS = "success"
    FAIL = "fail"
    SKIPPED = "skipped"


@dataclass
class AtomicOutcome:
    status: AtomicStatus
    details: dict[str, Any]
    error: str | None = None

    @classmethod
    def ok(cls, **details: Any) -> AtomicOutcome:
        return cls(AtomicStatus.SUCCESS, details)

    @classmethod
    def failed(cls, error: str, **details: Any) -> AtomicOutcome:
        return cls(AtomicStatus.FAIL, details, error=error)

    @classmethod
    def skipped(cls, reason: str, **details: Any) -> AtomicOutcome:
        return cls(AtomicStatus.SKIPPED, {"reason": reason, **details})


class Atomic(abc.ABC):
    """One lab-safe emulation of an ATT&CK (sub-)technique."""

    technique_id: ClassVar[str]
    technique_name: ClassVar[str]
    #: Short, stable identifier used to select the atomic via head options.
    name: ClassVar[str]
    platforms: ClassVar[frozenset[Platform]]
    #: True if the real technique needs elevation; such atomics degrade to
    #: SKIPPED rather than fail when not elevated.
    requires_admin: ClassVar[bool] = False

    def applicable(self) -> bool:
        return current_platform() in self.platforms

    @abc.abstractmethod
    def execute(self, env: AtomicEnv) -> AtomicOutcome:
        """Perform the benign emulation. Never raises."""

    def revert(self, env: AtomicEnv) -> None:  # noqa: B027 - optional hook, no-op by default
        """Idempotent cleanup — safe to call repeatedly, even if execute() did
        nothing. Default: no state to undo (stateless atomics)."""


def resolve_local_target(scope: EngagementScope) -> str | None:
    """The in-scope name authorizing emulation on *this* machine, or None.

    Execution/persistence run locally, so the operator authorizes them by
    listing ``localhost``, ``127.0.0.1``, or the hostname in the engagement
    scope. Returns the matching name so the head can log against it.
    """
    for candidate in ("localhost", "127.0.0.1", socket.gethostname()):
        if scope.is_target_in_scope(candidate):
            return candidate
    return None


__all__ = ["Atomic", "AtomicOutcome", "AtomicStatus", "resolve_local_target"]
