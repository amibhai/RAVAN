"""Tests for the TechniqueEvent structured-log schema."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ravan.schemas.events import Outcome, Tactic, TechniqueEvent


def test_minimal_event_has_tz_aware_default_timestamp() -> None:
    event = TechniqueEvent(
        attack_id="T1595",
        tactic=Tactic.RECONNAISSANCE,
        target="10.10.0.5",
        outcome=Outcome.SUCCESS,
    )
    assert event.timestamp.tzinfo is not None
    assert event.details == {}
    assert event.tactic is Tactic.RECONNAISSANCE
    assert event.outcome is Outcome.SUCCESS


def test_json_roundtrip_preserves_fields() -> None:
    event = TechniqueEvent(
        timestamp=datetime(2026, 6, 1, tzinfo=UTC),
        attack_id="T1110",
        tactic=Tactic.CREDENTIAL_ACCESS,
        target="lab.local",
        outcome=Outcome.BLOCKED,
        details={"reason": "out of scope"},
        technique_name="Brute Force",
        head="creds",
    )
    restored = TechniqueEvent.model_validate_json(event.model_dump_json())
    assert restored == event
    # Enums serialize to their slug values in JSON.
    assert '"tactic":"credential-access"' in event.model_dump_json()
    assert '"outcome":"blocked"' in event.model_dump_json()


def test_naive_timestamp_is_assumed_utc() -> None:
    event = TechniqueEvent(
        timestamp=datetime(2026, 6, 1, 12, 0, 0),  # naive
        attack_id="T1595",
        tactic=Tactic.RECONNAISSANCE,
        target="10.10.0.5",
        outcome=Outcome.SUCCESS,
    )
    assert event.timestamp.tzinfo is UTC


def test_invalid_outcome_is_rejected() -> None:
    with pytest.raises(ValidationError):
        TechniqueEvent(
            attack_id="T1595",
            tactic=Tactic.RECONNAISSANCE,
            target="10.10.0.5",
            outcome="exploded",  # type: ignore[arg-type]
        )


def test_empty_attack_id_is_rejected() -> None:
    with pytest.raises(ValidationError):
        TechniqueEvent(
            attack_id="   ",
            tactic=Tactic.RECONNAISSANCE,
            target="10.10.0.5",
            outcome=Outcome.SUCCESS,
        )


def test_event_is_immutable() -> None:
    event = TechniqueEvent(
        attack_id="T1595",
        tactic=Tactic.RECONNAISSANCE,
        target="10.10.0.5",
        outcome=Outcome.SUCCESS,
    )
    with pytest.raises(ValidationError):
        event.target = "changed"  # type: ignore[misc]


def test_unknown_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        TechniqueEvent(
            attack_id="T1595",
            tactic=Tactic.RECONNAISSANCE,
            target="10.10.0.5",
            outcome=Outcome.SUCCESS,
            bogus="nope",  # type: ignore[call-arg]
        )
