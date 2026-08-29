"""IMAP credential attacker (stdlib imaplib)."""

from __future__ import annotations

import contextlib
import imaplib
import time

from ravan.credential.attempt import AttemptResult, AttemptStatus
from ravan.credential.base import ProtocolAttacker


class IMAPAttacker(ProtocolAttacker):
    protocol = "imap"
    default_port = 143

    def authenticate(
        self, host: str, port: int, username: str, password: str, timeout: float
    ) -> AttemptResult:
        started = time.monotonic()
        conn: imaplib.IMAP4 | None = None
        try:
            conn = imaplib.IMAP4(host, port, timeout=timeout)
            banner = (
                conn.welcome.decode("utf-8", "replace")
                if isinstance(conn.welcome, bytes)
                else str(conn.welcome)
            )
            conn.login(username, password)  # raises IMAP4.error on bad creds
            return self._result(
                host,
                port,
                username,
                password,
                AttemptStatus.SUCCESS,
                banner=banner,
                response_time=time.monotonic() - started,
            )
        except imaplib.IMAP4.error as exc:
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
                with contextlib.suppress(imaplib.IMAP4.error, OSError):
                    conn.logout()


__all__ = ["IMAPAttacker"]
