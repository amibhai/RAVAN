"""Persistence head (Head #5) — benign, self-cleaning autostart artifacts.

Runs lab-safe atomics that establish user-level persistence (registry Run key,
startup file, scheduled task, systemd user service, launch agent, shell profile)
pointing at a harmless canary, then removes them on cleanup. MITRE ATT&CK
Persistence (T1547, T1053, T1543, T1546).

By default every artifact is reverted after the run (lab-safe). Set the ``keep``
option to leave persistence in place for a longer detection test — the head then
logs what remains and how to remove it.
"""

from __future__ import annotations

from ravan.core.base import RunContext
from ravan.emulation.head import LocalAtomicHead
from ravan.heads.persistence.atomics import PERSISTENCE_ATOMICS
from ravan.schemas.events import Outcome, Tactic


class PersistenceHead(LocalAtomicHead):
    head_name = "persistence"
    technique_id = "T1547"
    technique_name = "Boot or Logon Autostart Execution"
    tactic = Tactic.PERSISTENCE
    required_permissions = ("persistence-emulation",)
    description = "Persistence: benign, self-cleaning autostart artifacts (T1547/T1053/T1543)."
    atomics = PERSISTENCE_ATOMICS

    def _post_run(self, context: RunContext, target: str) -> None:
        if self._keep and self._reverts:
            context.record(
                target=target,
                outcome=Outcome.SUCCESS,
                details={
                    "note": (
                        "persistence artifacts left in place (keep=true); re-run with "
                        "keep=false to remove them, or delete them manually"
                    ),
                    "artifacts_kept": len(self._reverts),
                },
                attack_id=self.technique_id,
                technique_name=self.technique_name,
            )


__all__ = ["PersistenceHead"]
