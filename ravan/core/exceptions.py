"""Exception hierarchy for the RAVAN core engine."""

from __future__ import annotations

from collections.abc import Iterable


class RavanError(Exception):
    """Base class for all RAVAN errors."""


class ScopeConfigError(RavanError):
    """The engagement scope file is missing, malformed, or invalid."""


class ScopeViolation(RavanError):
    """An action was refused because it falls outside the engagement scope.

    Raised for out-of-scope tactics, targets, techniques, missing permissions,
    or actions attempted outside the engagement time window. Every scope
    violation is also recorded as a ``BLOCKED`` :class:`TechniqueEvent`.
    """


class HeadNotFound(RavanError):
    """No head is registered under the requested name."""

    def __init__(self, name: str, available: Iterable[str] = ()) -> None:
        self.name = name
        self.available = sorted(available)
        listing = ", ".join(self.available) if self.available else "(none)"
        super().__init__(f"no head named {name!r}; available heads: {listing}")


class HeadLoadError(RavanError):
    """A head package could not be imported or is missing required metadata."""


class DuplicateHeadError(RavanError):
    """Two distinct head classes claim the same ``head_name``."""


__all__ = [
    "DuplicateHeadError",
    "HeadLoadError",
    "HeadNotFound",
    "RavanError",
    "ScopeConfigError",
    "ScopeViolation",
]
