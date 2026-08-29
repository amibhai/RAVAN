"""POP3 credential attacker (stdlib poplib)."""

from __future__ import annotations

import contextlib
import poplib
import time

from ravan.credential.attempt import AttemptResult, AttemptStatus
from ravan.credential.base import ProtocolAttacker


class POP3Attacker(ProtocolAttacker):
    protocol = "pop3"
    default_port = 110

    def authenticate(
        self, host: str, port: int, username: str, password: str, timeout: float
    ) -> AttemptResult:
        started = time.monotonic()
        conn: poplib.POP3 | None = None
        try:
            conn = poplib.POP3(host, port, timeout=timeout)
            banner = conn.getwelcome().decode("utf-8", "replace")
            conn.user(username)
            conn.pass_(password)  # raises poplib.error_proto on bad creds
            return self._result(
                host,
                port,
                username,
                password,
                AttemptStatus.SUCCESS,
                banner=banner,
                response_time=time.monotonic() - started,
            )
        except poplib.error_proto as exc:
            return self._result(
                host, port, username, password, AttemptStatus.FAILED, error=str(exc)
            )
        except TimeoutError as exc:
            return self._result(
                host, port, username, password, AttemptStatus.TIMEOUT, error=str(exc)
            )
        except OSError as exc:
            return self._result(host, port, username, password, AttemptStatus.ERROR, error=str(exc))
        finally:
            if conn is not None:
                with contextlib.suppress(poplib.error_proto, OSError):
                    conn.quit()


__all__ = ["POP3Attacker"]
