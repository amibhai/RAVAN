"""Engagement scope: the authorized-use allow-list, enforced in code.

The engine loads an ``engagement.yaml`` scope file and refuses to act outside
it. Scope enforcement is *structural*: the checks live here and in the engine,
not as a courtesy each head is trusted to remember.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from ravan.core.exceptions import ScopeConfigError
from ravan.schemas.events import Tactic


def normalize_tactic(value: str) -> Tactic:
    """Coerce a free-form tactic string into a :class:`Tactic`.

    Accepts case-insensitive slugs with spaces or underscores, e.g.
    ``"Resource Development"`` -> ``Tactic.RESOURCE_DEVELOPMENT``.
    """
    slug = str(value).strip().lower().replace(" ", "-").replace("_", "-")
    try:
        return Tactic(slug)
    except ValueError as exc:
        valid = ", ".join(t.value for t in Tactic)
        raise ScopeConfigError(
            f"unknown ATT&CK tactic {value!r}; valid tactics: {valid}"
        ) from exc


def _parse_timestamp(value: Any, field_name: str) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ScopeConfigError(
                f"time_window.{field_name} is not a valid ISO-8601 datetime: {value!r}"
            ) from exc
    else:
        raise ScopeConfigError(
            f"time_window.{field_name} must be a datetime or ISO-8601 string, "
            f"got {type(value).__name__}"
        )
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _as_str_tuple(value: Any, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise ScopeConfigError(f"{field_name} must be a list, got {type(value).__name__}")
    return tuple(str(item).strip() for item in value if str(item).strip())


@dataclass(frozen=True)
class EngagementScope:
    """A parsed, validated engagement scope allow-list."""

    name: str
    targets: tuple[str, ...]
    allowed_tactics: frozenset[Tactic]
    allowed_techniques: frozenset[str]
    permissions: frozenset[str]
    window_start: datetime | None = None
    window_end: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # -- construction ---------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path) -> EngagementScope:
        """Load and validate a scope from a YAML file."""
        p = Path(path)
        if not p.is_file():
            raise ScopeConfigError(f"engagement scope file not found: {p}")
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ScopeConfigError(f"could not parse YAML in {p}: {exc}") from exc
        if not isinstance(raw, Mapping):
            raise ScopeConfigError(
                f"engagement scope file {p} must contain a top-level mapping"
            )
        return cls.from_mapping(raw)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> EngagementScope:
        """Build and validate a scope from an already-parsed mapping."""
        name = str(data.get("name", "unnamed-engagement")).strip() or "unnamed-engagement"

        scope_block = data.get("scope", data)
        if not isinstance(scope_block, Mapping):
            raise ScopeConfigError("'scope' must be a mapping of targets/tactics/etc.")

        targets = _as_str_tuple(scope_block.get("targets"), "scope.targets")
        if not targets:
            raise ScopeConfigError(
                "engagement scope must declare at least one target under scope.targets"
            )

        raw_tactics = _as_str_tuple(scope_block.get("allowed_tactics"), "scope.allowed_tactics")
        if not raw_tactics:
            raise ScopeConfigError(
                "engagement scope must declare at least one tactic under scope.allowed_tactics"
            )
        allowed_tactics = frozenset(normalize_tactic(t) for t in raw_tactics)

        raw_techniques = _as_str_tuple(
            scope_block.get("allowed_techniques"), "scope.allowed_techniques"
        )
        allowed_techniques = frozenset(t.upper() for t in raw_techniques)
        permissions = frozenset(_as_str_tuple(scope_block.get("permissions"), "scope.permissions"))

        window = scope_block.get("time_window") or {}
        if not isinstance(window, Mapping):
            raise ScopeConfigError("scope.time_window must be a mapping with start/end")
        window_start = _parse_timestamp(window.get("start"), "start")
        window_end = _parse_timestamp(window.get("end"), "end")
        if window_start and window_end and window_start > window_end:
            raise ScopeConfigError("time_window.start must not be after time_window.end")

        metadata = {
            k: v for k, v in data.items() if k not in {"name", "scope"}
        }

        return cls(
            name=name,
            targets=targets,
            allowed_tactics=allowed_tactics,
            allowed_techniques=allowed_techniques,
            permissions=permissions,
            window_start=window_start,
            window_end=window_end,
            metadata=metadata,
        )

    # -- enforcement checks ---------------------------------------------------

    def is_tactic_allowed(self, tactic: Tactic | str) -> bool:
        t = tactic if isinstance(tactic, Tactic) else normalize_tactic(tactic)
        return t in self.allowed_tactics

    def is_technique_allowed(self, technique_id: str) -> bool:
        """An empty ``allowed_techniques`` means any technique within an allowed
        tactic is permitted; a non-empty list restricts to those IDs."""
        if not self.allowed_techniques:
            return True
        return technique_id.strip().upper() in self.allowed_techniques

    def is_target_in_scope(self, target: str) -> bool:
        """True if ``target`` matches an allowed host or falls inside an allowed
        IP network/CIDR."""
        candidate = target.strip().lower()
        if not candidate:
            return False

        try:
            candidate_ip = ipaddress.ip_address(candidate)
        except ValueError:
            candidate_ip = None

        for allowed in self.targets:
            allowed_norm = allowed.strip().lower()
            if allowed_norm == candidate:
                return True
            if candidate_ip is not None:
                try:
                    network = ipaddress.ip_network(allowed_norm, strict=False)
                except ValueError:
                    continue
                if candidate_ip in network:
                    return True
        return False

    def is_within_window(self, now: datetime) -> bool:
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)
        after_start = self.window_start is None or now >= self.window_start
        before_end = self.window_end is None or now <= self.window_end
        return after_start and before_end

    def missing_permissions(self, required: Iterable[str]) -> tuple[str, ...]:
        """Return the subset of ``required`` permissions the scope does not grant."""
        return tuple(p for p in required if p not in self.permissions)


__all__ = ["EngagementScope", "normalize_tactic"]
