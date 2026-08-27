"""Reconnaissance head (Head #1).

Phase 0 placeholder. It wires the reconnaissance tactic into the plugin
interface and exercises the full scope-gated action + structured-logging path,
but performs **no real network activity yet** — the SHIV-reconnaissance_toolkit
logic is ported in Phase 1. Every "probe" here is a logged no-op.
"""

from __future__ import annotations

from ravan.core.base import BaseHead, RunContext
from ravan.schemas.events import HeadReport, Outcome, Tactic


class ReconHead(BaseHead):
    head_name = "recon"
    technique_id = "T1595"
    technique_name = "Active Scanning"
    tactic = Tactic.RECONNAISSANCE
    required_permissions = ("active-scan",)
    description = (
        "Reconnaissance head - placeholder in Phase 0; ports "
        "SHIV-reconnaissance_toolkit in Phase 1."
    )

    def __init__(self) -> None:
        self._processed: list[str] = []

    def run(self, context: RunContext) -> None:
        for target in context.targets:
            # authorize() is the structural per-target scope gate: it logs a
            # BLOCKED event and raises if the target is out of scope.
            authorized = context.authorize(target)
            # Phase 0: simulated, no-op reachability probe (nothing hits the wire).
            context.record(
                target=authorized,
                outcome=Outcome.SUCCESS,
                details={
                    "probe": "noop-placeholder",
                    "note": "real reconnaissance is implemented in Phase 1",
                },
            )
            self._processed.append(authorized)

    def report(self) -> HeadReport:
        return self.build_report(
            summary=(
                f"recon placeholder processed {len(self._processed)} in-scope "
                f"target(s): {', '.join(self._processed) or '(none)'}"
            )
        )

    def cleanup(self) -> None:
        self._processed.clear()
