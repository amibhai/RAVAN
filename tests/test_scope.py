"""Tests for engagement scope loading and enforcement checks."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from ravan.core.exceptions import ScopeConfigError
from ravan.core.scope import EngagementScope, normalize_tactic
from ravan.schemas.events import Tactic

from conftest import make_scope

EXAMPLE = Path(__file__).resolve().parents[1] / "engagements" / "example.yaml"


def test_loads_example_engagement_file() -> None:
    scope = EngagementScope.from_file(EXAMPLE)
    assert scope.name == "home-lab-range"
    assert "lab.local" in scope.targets
    assert Tactic.RECONNAISSANCE in scope.allowed_tactics
    assert "active-scan" in scope.permissions
    assert scope.window_start is not None and scope.window_end is not None


def test_target_exact_hostname_match() -> None:
    scope = make_scope()
    assert scope.is_target_in_scope("lab.local")
    assert scope.is_target_in_scope("LAB.LOCAL")  # case-insensitive


def test_target_ip_within_cidr() -> None:
    scope = make_scope()
    assert scope.is_target_in_scope("10.10.0.42")


def test_out_of_scope_ip_is_rejected() -> None:
    scope = make_scope()
    assert not scope.is_target_in_scope("203.0.113.9")


def test_out_of_scope_host_is_rejected() -> None:
    scope = make_scope()
    assert not scope.is_target_in_scope("evil.example.com")


def test_tactic_allow_list() -> None:
    scope = make_scope()
    assert scope.is_tactic_allowed(Tactic.RECONNAISSANCE)
    assert scope.is_tactic_allowed("Resource Development")  # normalized
    assert not scope.is_tactic_allowed(Tactic.EXFILTRATION)


def test_empty_technique_list_allows_any() -> None:
    scope = make_scope()
    assert scope.is_technique_allowed("T1595")
    assert scope.is_technique_allowed("T9999")


def test_technique_allow_list_restricts() -> None:
    scope = make_scope(scope={"allowed_techniques": ["T1595"]})
    assert scope.is_technique_allowed("t1595")  # case-insensitive
    assert not scope.is_technique_allowed("T1110")


def test_time_window_bounds() -> None:
    scope = make_scope()
    inside = datetime(2026, 6, 1, tzinfo=UTC)
    before = datetime(2025, 1, 1, tzinfo=UTC)
    after = datetime(2028, 1, 1, tzinfo=UTC)
    assert scope.is_within_window(inside)
    assert not scope.is_within_window(before)
    assert not scope.is_within_window(after)


def test_open_time_window_always_valid() -> None:
    scope = make_scope(scope={"time_window": {}})
    assert scope.window_start is None and scope.window_end is None
    assert scope.is_within_window(datetime(1999, 1, 1, tzinfo=UTC))


def test_missing_permissions_reported() -> None:
    scope = make_scope()
    assert scope.missing_permissions(["active-scan"]) == ()
    assert scope.missing_permissions(["active-scan", "network-spoof"]) == ("network-spoof",)


def test_unknown_tactic_raises() -> None:
    with pytest.raises(ScopeConfigError):
        normalize_tactic("teleportation")
    with pytest.raises(ScopeConfigError):
        make_scope(scope={"allowed_tactics": ["teleportation"]})


def test_missing_targets_raises() -> None:
    with pytest.raises(ScopeConfigError):
        make_scope(scope={"targets": []})


def test_missing_tactics_raises() -> None:
    with pytest.raises(ScopeConfigError):
        make_scope(scope={"allowed_tactics": []})


def test_start_after_end_raises() -> None:
    with pytest.raises(ScopeConfigError):
        make_scope(
            scope={"time_window": {"start": "2027-01-01T00:00:00Z", "end": "2026-01-01T00:00:00Z"}}
        )
