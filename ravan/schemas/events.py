"""Structured logging schema for RAVAN.

Every action any head takes emits a :class:`TechniqueEvent`. Detection
validation (Phase 5) depends on this schema being consistent from head #1
onward, so it is defined once here and shared by the whole framework.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Tactic(StrEnum):
    """MITRE ATT&CK Enterprise tactic slugs.

    All 14 enterprise tactics are listed for correctness; RAVAN's ten heads
    map onto the subset marked in the README.
    """

    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class Outcome(StrEnum):
    """The result of a single emulated technique action."""

    SUCCESS = "success"
    FAIL = "fail"
    BLOCKED = "blocked"


def _utcnow() -> datetime:
    return datetime.now(UTC)


class TechniqueEvent(BaseModel):
    """A single, machine-readable record of one emulated technique action.

    Instances are immutable (``frozen``): once an action is logged it is a
    fact of the engagement record and must not be rewritten.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp: datetime = Field(default_factory=_utcnow)
    attack_id: str = Field(
        ...,
        description="MITRE ATT&CK technique ID, e.g. 'T1595'.",
    )
    tactic: Tactic
    target: str
    outcome: Outcome
    details: dict[str, Any] = Field(default_factory=dict)

    # Extra context that makes downstream detection validation richer.
    # Not required by the core contract but populated by the engine.
    technique_name: str | None = None
    head: str | None = None

    @field_validator("timestamp")
    @classmethod
    def _ensure_tz_aware(cls, value: datetime) -> datetime:
        """Naive timestamps are assumed to be UTC and made timezone-aware."""
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value

    @field_validator("attack_id")
    @classmethod
    def _non_empty_attack_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("attack_id must be a non-empty MITRE ATT&CK technique ID")
        return value


class HeadReport(BaseModel):
    """A head's self-summary of a single run.

    The engine's ``RunResult.events`` remains the authoritative log; this is the
    head's own human-oriented rollup, used by the CLI and later by the reporting
    layer (Phase 6).
    """

    model_config = ConfigDict(extra="forbid")

    head_name: str
    technique_id: str
    tactic: Tactic
    total_events: int = 0
    successes: int = 0
    failures: int = 0
    blocked: int = 0
    summary: str = ""
    events: list[TechniqueEvent] = Field(default_factory=list)


__all__ = ["HeadReport", "Outcome", "Tactic", "TechniqueEvent"]
