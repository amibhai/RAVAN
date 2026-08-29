"""Result model for a single credential attempt.

Shared by the credential-access and lateral-movement heads. Ported and slimmed
from credential-attacks-toolkit's result dataclasses.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AttemptStatus(StrEnum):
    """Outcome of one credential attempt against a service."""

    SUCCESS = "success"  # credentials accepted
    FAILED = "failed"  # credentials rejected
    LOCKOUT = "lockout"  # service signalled account lockout / rate limit
    ERROR = "error"  # connection/protocol error (not an auth verdict)
    TIMEOUT = "timeout"  # attempt timed out
    NOAUTH = "noauth"  # service accepts anyone / no auth required
    SKIPPED = "skipped"  # not attempted (already found, or locked out)
    UNSUPPORTED = "unsupported"  # protocol backend unavailable (missing dep)


# Statuses that mean the credential is valid / access was obtained.
_VALID = frozenset({AttemptStatus.SUCCESS, AttemptStatus.NOAUTH})


@dataclass(frozen=True)
class AttemptResult:
    """Immutable record of one credential attempt."""

    host: str
    port: int
    protocol: str
    username: str
    password: str
    status: AttemptStatus
    error: str | None = None
    banner: str | None = None
    response_time: float = 0.0

    @property
    def valid(self) -> bool:
        return self.status in _VALID

    @property
    def is_lockout(self) -> bool:
        return self.status is AttemptStatus.LOCKOUT

    def redacted(self) -> dict[str, object]:
        """A dict for structured logging. The password is intentionally kept —
        a discovered valid credential is the whole point of the engagement
        record — but callers may drop it if their policy requires."""
        out: dict[str, object] = {
            "protocol": self.protocol,
            "port": self.port,
            "username": self.username,
            "status": self.status.value,
        }
        if self.status in _VALID:
            out["password"] = self.password
        if self.banner:
            out["banner"] = self.banner[:160]
        if self.error:
            out["error"] = self.error[:200]
        return out


__all__ = ["AttemptResult", "AttemptStatus"]
