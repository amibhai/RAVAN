"""Shared base for heads that run local atomics (execution, persistence).

Handles the common lifecycle: authorize local emulation against the engagement
scope, select and filter atomics by platform and options, execute each with a
shared benign environment, emit an ATT&CK-tagged event per atomic, and revert
stateful atomics idempotently on cleanup.
"""

from __future__ import annotations

import contextlib
from typing import ClassVar

from ravan.core.base import BaseHead, RunContext
from ravan.emulation.atomic import Atomic, AtomicOutcome, AtomicStatus, resolve_local_target
from ravan.emulation.runner import AtomicEnv, marker, staging_dir
from ravan.schemas.events import HeadReport, Outcome


class LocalAtomicHead(BaseHead):
    """A head whose atomics emulate techniques on the local machine."""

    #: The atomics this head can run, in a stable order.
    atomics: ClassVar[list[type[Atomic]]] = []

    def __init__(self) -> None:
        self._executed = 0
        self._failed = 0
        self._skipped = 0
        self._keep = False
        self._reverts: list[tuple[Atomic, AtomicEnv]] = []

    # -- lifecycle ------------------------------------------------------------

    def run(self, context: RunContext) -> None:
        target = resolve_local_target(context.scope)
        if target is None:
            context.record(
                target=f"engagement:{context.scope.name}",
                outcome=Outcome.BLOCKED,
                details={
                    "reason": (
                        "local emulation is not authorized: add localhost, 127.0.0.1, "
                        "or this host's name to scope.targets"
                    )
                },
            )
            return
        context.authorize(target)
        self._keep = bool(context.option("keep", False))

        env = AtomicEnv(
            marker=marker(),
            staging=staging_dir(context.scope.name),
            timeout=float(context.option("timeout", 15.0)),
            options=dict(context.options),
        )

        for atomic in self._selected(context):
            if not atomic.applicable():
                self._skipped += 1
                continue
            outcome = self._safe_execute(atomic, env)
            if outcome.status is not AtomicStatus.SKIPPED:
                self._reverts.append((atomic, env))
            self._emit(context, atomic, target, outcome)

        self._post_run(context, target)

    def _post_run(self, context: RunContext, target: str) -> None:
        """Hook called after all atomics run. Default: nothing."""

    def report(self) -> HeadReport:
        summary = (
            f"{self.head_name}: {self._executed} atomic(s) executed, "
            f"{self._failed} failed, {self._skipped} not applicable/available"
        )
        return self.build_report(summary=summary)

    def cleanup(self) -> None:
        # Revert in reverse order (idempotent, must not raise) unless the
        # operator asked to keep the artifacts in place.
        if not self._keep:
            for atomic, env in reversed(self._reverts):
                # cleanup must never propagate
                with contextlib.suppress(Exception):
                    atomic.revert(env)
        self._reverts.clear()

    # -- helpers --------------------------------------------------------------

    def _selected(self, context: RunContext) -> list[Atomic]:
        want = context.option("atomics")
        names = {str(n) for n in want} if isinstance(want, (list, tuple)) and want else None
        selected: list[Atomic] = []
        for cls in self.atomics:
            instance = cls()
            if names is not None and instance.name not in names:
                continue
            selected.append(instance)
        return selected

    def _safe_execute(self, atomic: Atomic, env: AtomicEnv) -> AtomicOutcome:
        try:
            return atomic.execute(env)
        except Exception as exc:  # one atomic must not sink the head
            return AtomicOutcome.failed(f"atomic raised: {exc!r}")

    def _emit(
        self, context: RunContext, atomic: Atomic, target: str, outcome: AtomicOutcome
    ) -> None:
        if outcome.status is AtomicStatus.SKIPPED:
            self._skipped += 1
            return
        if outcome.status is AtomicStatus.FAIL:
            self._failed += 1
            event_outcome = Outcome.FAIL
        else:
            self._executed += 1
            event_outcome = Outcome.SUCCESS
        details = {"atomic": atomic.name, **outcome.details}
        if outcome.error:
            details["error"] = outcome.error
        context.record(
            target=target,
            outcome=event_outcome,
            details=details,
            attack_id=atomic.technique_id,
            technique_name=atomic.technique_name,
        )


__all__ = ["LocalAtomicHead"]
