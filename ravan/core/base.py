"""The plugin contract every head implements, and the per-run context the
engine hands it.

A *head* is a self-contained ATT&CK tactic module. The engine owns scope
enforcement; a head receives a :class:`RunContext` and performs its emulated
actions *through it*, so target checks and structured logging happen on the
sanctioned path rather than being reimplemented per head.
"""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING, Any, ClassVar, cast

from ravan.core.exceptions import ScopeViolation
from ravan.core.sinks import EventSink
from ravan.schemas.events import HeadReport, Outcome, Tactic, TechniqueEvent

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

    from ravan.core.scope import EngagementScope


class RunContext:
    """Everything a head is allowed to touch during a single run.

    The context is the head's only sanctioned way to act on a target and to
    emit events. :meth:`authorize` is the structural per-target scope gate:
    an out-of-scope target is logged as ``BLOCKED`` and refused.
    """

    def __init__(
        self,
        *,
        head: BaseHead,
        scope: EngagementScope,
        sink: EventSink,
        clock: Callable[[], datetime],
        options: dict[str, Any] | None = None,
    ) -> None:
        self._head = head
        self._scope = scope
        self._sink = sink
        self._clock = clock
        #: Per-run head configuration, merged from the engagement's ``heads``
        #: block and any CLI overrides. Heads read their tuning from here.
        self.options: dict[str, Any] = dict(options or {})
        self.events: list[TechniqueEvent] = []

    @property
    def head(self) -> BaseHead:
        return self._head

    @property
    def scope(self) -> EngagementScope:
        return self._scope

    @property
    def targets(self) -> tuple[str, ...]:
        """The engagement's declared, in-scope targets."""
        return self._scope.targets

    def now(self) -> datetime:
        return self._clock()

    def option(self, key: str, default: Any = None) -> Any:
        """Read a per-run head option (from the engagement ``heads`` block or a
        CLI ``--option`` override)."""
        return self.options.get(key, default)

    def authorize(self, target: str) -> str:
        """Structural per-target scope gate.

        Returns ``target`` unchanged if it is in scope. Otherwise records a
        ``BLOCKED`` event and raises :class:`ScopeViolation`. A head cannot act
        on a target through the sanctioned path without this check running.
        """
        if not self._scope.is_target_in_scope(target):
            self.record(
                target=target,
                outcome=Outcome.BLOCKED,
                details={"reason": "target is not in the engagement scope"},
            )
            raise ScopeViolation(
                f"target {target!r} is not in the engagement scope for "
                f"head {self._head.head_name!r}"
            )
        return target

    def record(
        self,
        *,
        target: str,
        outcome: Outcome,
        details: dict[str, Any] | None = None,
        attack_id: str | None = None,
        technique_name: str | None = None,
    ) -> TechniqueEvent:
        """Build, store, and emit a :class:`TechniqueEvent` for this head."""
        event = TechniqueEvent(
            timestamp=self._clock(),
            attack_id=attack_id or self._head.technique_id,
            tactic=self._head.tactic,
            target=target,
            outcome=outcome,
            details=details or {},
            technique_name=technique_name or self._head.technique_name,
            head=self._head.head_name,
        )
        self.events.append(event)
        self._sink(event)
        return event


class BaseHead(abc.ABC):
    """Abstract base class every head plugin implements.

    Subclasses declare metadata as class attributes and implement
    :meth:`run`, :meth:`report`, and :meth:`cleanup`.
    """

    #: Short unique name used on the CLI and as the registry key (e.g. "recon").
    head_name: ClassVar[str]
    #: MITRE ATT&CK technique ID this head primarily emulates (e.g. "T1595").
    technique_id: ClassVar[str]
    #: Human-readable technique name (e.g. "Active Scanning").
    technique_name: ClassVar[str]
    #: The ATT&CK tactic this head belongs to.
    tactic: ClassVar[Tactic]
    #: Scope permissions this head requires before the engine will run it.
    required_permissions: ClassVar[tuple[str, ...]] = ()
    #: One-line description shown by ``ravan list``.
    description: ClassVar[str] = ""

    # Populated by the engine immediately before run(); the authoritative
    # per-run event log for this head instance.
    _run_events: list[TechniqueEvent]

    @property
    def events(self) -> list[TechniqueEvent]:
        return cast("list[TechniqueEvent]", getattr(self, "_run_events", []))

    @abc.abstractmethod
    def run(self, context: RunContext) -> None:
        """Perform the head's emulated technique actions.

        All target actions and logging must go through ``context``.
        """

    @abc.abstractmethod
    def report(self) -> HeadReport:
        """Return this head's self-summary of the most recent run."""

    @abc.abstractmethod
    def cleanup(self) -> None:
        """Release any resources / undo lab-side changes made during the run."""

    # -- convenience for subclasses ------------------------------------------

    def build_report(self, summary: str = "") -> HeadReport:
        """Default report builder derived from the run's events."""
        events = self.events
        return HeadReport(
            head_name=self.head_name,
            technique_id=self.technique_id,
            tactic=self.tactic,
            total_events=len(events),
            successes=sum(1 for e in events if e.outcome is Outcome.SUCCESS),
            failures=sum(1 for e in events if e.outcome is Outcome.FAIL),
            blocked=sum(1 for e in events if e.outcome is Outcome.BLOCKED),
            summary=summary,
            events=list(events),
        )


__all__ = ["BaseHead", "RunContext"]
