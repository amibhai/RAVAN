"""The RAVAN engine: scope enforcement, dispatch, and plugin isolation.

The engine is the single choke point for authorized-use enforcement. Before a
head runs, the engine checks — on the head's behalf, not trusting the head to do
it — that the head's tactic is in scope, its required permissions are granted,
and the current time is inside the engagement window. Per-target checks are
provided to the head via :class:`RunContext`. A crash inside one head is caught
and logged; it cannot take down the engine.
"""

from __future__ import annotations

import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ravan.core.base import BaseHead, RunContext
from ravan.core.exceptions import HeadNotFound, ScopeViolation
from ravan.core.loader import HeadLoader, Loader
from ravan.core.scope import EngagementScope
from ravan.core.sinks import EventSink, ListSink
from ravan.schemas.events import HeadReport, Outcome, TechniqueEvent


@dataclass
class RunResult:
    """The outcome of dispatching a single head."""

    head_name: str
    status: str  # "ok" | "error" | "scope-violation"
    events: list[TechniqueEvent] = field(default_factory=list)
    report: HeadReport | None = None


class Engine:
    """Loads a scope, enforces it, and dispatches heads."""

    def __init__(
        self,
        scope: EngagementScope,
        *,
        sink: EventSink | None = None,
        loader: Loader | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.scope = scope
        self.sink: EventSink = sink if sink is not None else ListSink()
        self.loader: Loader = loader if loader is not None else HeadLoader()
        self.clock: Callable[[], datetime] = clock or (lambda: datetime.now(UTC))

    # -- discovery ------------------------------------------------------------

    def available_heads(self) -> dict[str, type[BaseHead]]:
        return self.loader.discover()

    # -- dispatch -------------------------------------------------------------

    def run_head(self, head_name: str) -> RunResult:
        """Instantiate, scope-check, and run a head.

        Raises :class:`HeadNotFound` for an unknown head and
        :class:`ScopeViolation` for a whole-head scope refusal (disallowed
        tactic/technique, missing permission, or out-of-window). Per-target
        refusals and head crashes do not raise: they are logged and reflected in
        the result status.
        """
        heads = self.loader.discover()
        head_cls = heads.get(head_name)
        if head_cls is None:
            raise HeadNotFound(head_name, heads.keys())

        head = head_cls()
        # Whole-head scope preflight. Emits a BLOCKED event and raises on refusal.
        self._preflight(head)

        # Every event produced during this run (head- or engine-emitted) is
        # captured here so RunResult.events is the authoritative per-run log.
        captured: list[TechniqueEvent] = []

        def run_sink(event: TechniqueEvent) -> None:
            captured.append(event)
            self.sink(event)

        context = RunContext(head=head, scope=self.scope, sink=run_sink, clock=self.clock)
        head._run_events = context.events  # what the head's own report() reads

        status = "ok"
        report: HeadReport | None = None
        try:
            try:
                head.run(context)
            except ScopeViolation:
                # A BLOCKED event was already emitted by RunContext.authorize.
                status = "scope-violation"
            except Exception as exc:
                status = "error"
                self._emit(
                    run_sink,
                    head,
                    target="*",
                    outcome=Outcome.FAIL,
                    details={
                        "reason": "head raised during run()",
                        "error": repr(exc),
                        "traceback": traceback.format_exc(),
                    },
                )
            # Report before teardown, so the head can summarize its run before
            # cleanup() releases the state it describes.
            report = self._safe_report(head, run_sink)
        finally:
            # cleanup() always runs, even if run()/report() failed hard.
            self._safe_cleanup(head, run_sink)

        return RunResult(
            head_name=head_name,
            status=status,
            events=captured,
            report=report,
        )

    # -- scope enforcement (engine-side, structural) --------------------------

    def _preflight(self, head: BaseHead) -> None:
        now = self.clock()

        if not self.scope.is_tactic_allowed(head.tactic):
            self._refuse(
                head,
                reason=f"tactic {head.tactic.value!r} is not in the engagement's allowed_tactics",
            )

        if not self.scope.is_technique_allowed(head.technique_id):
            self._refuse(
                head,
                reason=(
                    f"technique {head.technique_id!r} is not in the engagement's "
                    "allowed_techniques"
                ),
            )

        missing = self.scope.missing_permissions(head.required_permissions)
        if missing:
            self._refuse(
                head,
                reason=(
                    "engagement scope does not grant required permissions: "
                    f"{', '.join(missing)}"
                ),
            )

        if not self.scope.is_within_window(now):
            self._refuse(head, reason="current time is outside the engagement time window")

    def _refuse(self, head: BaseHead, *, reason: str) -> None:
        self._emit(
            self.sink,
            head,
            target=f"engagement:{self.scope.name}",
            outcome=Outcome.BLOCKED,
            details={"reason": reason},
        )
        raise ScopeViolation(f"refused to run head {head.head_name!r}: {reason}")

    # -- helpers --------------------------------------------------------------

    def _emit(
        self,
        sink: EventSink,
        head: BaseHead,
        *,
        target: str,
        outcome: Outcome,
        details: dict[str, object],
    ) -> TechniqueEvent:
        event = TechniqueEvent(
            timestamp=self.clock(),
            attack_id=head.technique_id,
            tactic=head.tactic,
            target=target,
            outcome=outcome,
            details=dict(details),
            technique_name=head.technique_name,
            head=head.head_name,
        )
        sink(event)
        return event

    def _safe_cleanup(self, head: BaseHead, sink: EventSink) -> None:
        try:
            head.cleanup()
        except Exception as exc:
            self._emit(
                sink,
                head,
                target="*",
                outcome=Outcome.FAIL,
                details={"reason": "head raised during cleanup()", "error": repr(exc)},
            )

    def _safe_report(self, head: BaseHead, sink: EventSink) -> HeadReport | None:
        try:
            return head.report()
        except Exception as exc:
            self._emit(
                sink,
                head,
                target="*",
                outcome=Outcome.FAIL,
                details={"reason": "head raised during report()", "error": repr(exc)},
            )
            return None


__all__ = ["Engine", "RunResult"]
