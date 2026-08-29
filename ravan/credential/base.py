"""The interface every protocol attacker implements."""

from __future__ import annotations

import abc

from ravan.credential.attempt import AttemptResult, AttemptStatus

# Substrings in an error message that suggest the service is locking the account
# or rate-limiting — a signal to back off rather than keep guessing.
LOCKOUT_SIGNALS: tuple[str, ...] = (
    "locked",
    "lock out",
    "lockout",
    "too many",
    "account disabled",
    "account suspended",
    "temporarily blocked",
    "maximum authentication",
    "intruder detection",
    "rate limit",
    "try again later",
)


class ProtocolAttacker(abc.ABC):
    """Base class for all protocol-specific credential testers.

    A subclass sets :attr:`protocol` and :attr:`default_port` and implements
    :meth:`authenticate`, which must never raise — it catches every error and
    returns an :class:`AttemptResult` with an appropriate status.
    """

    protocol: str = ""
    default_port: int = 0
    #: True if this backend needs an optional dependency that may be absent.
    optional: bool = False

    @abc.abstractmethod
    def authenticate(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        timeout: float,
    ) -> AttemptResult:
        """Attempt one credential pair. Never raises."""

    @classmethod
    def available(cls) -> bool:
        """Whether this backend can run (its dependency is importable)."""
        return True

    @classmethod
    def from_config(cls, config: dict[str, object]) -> ProtocolAttacker:
        """Build an attacker from a per-protocol options dict. Config-driven
        protocols (HTTP form, telnet, ...) override this to read their keys."""
        return cls()

    def detect_lockout(self, error: str) -> bool:
        low = error.lower()
        return any(signal in low for signal in LOCKOUT_SIGNALS)

    def _result(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        status: AttemptStatus,
        *,
        error: str | None = None,
        banner: str | None = None,
        response_time: float = 0.0,
    ) -> AttemptResult:
        # Promote a generic failure to LOCKOUT when the error text says so.
        if status is AttemptStatus.FAILED and error and self.detect_lockout(error):
            status = AttemptStatus.LOCKOUT
        return AttemptResult(
            host=host,
            port=port,
            protocol=self.protocol,
            username=username,
            password=password,
            status=status,
            error=error,
            banner=banner,
            response_time=response_time,
        )


__all__ = ["LOCKOUT_SIGNALS", "ProtocolAttacker"]
