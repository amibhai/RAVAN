"""SMTP-AUTH credential attacker (stdlib smtplib, with STARTTLS)."""

from __future__ import annotations

import contextlib
import smtplib
import ssl
import time

from ravan.credential.attempt import AttemptResult, AttemptStatus
from ravan.credential.base import ProtocolAttacker


class SMTPAttacker(ProtocolAttacker):
    protocol = "smtp"
    default_port = 587

    def authenticate(
        self, host: str, port: int, username: str, password: str, timeout: float
    ) -> AttemptResult:
        started = time.monotonic()
        server: smtplib.SMTP | None = None
        try:
            server = smtplib.SMTP(host, port, timeout=timeout)
            banner = server.ehlo()[1].decode("utf-8", "replace") if server.ehlo_resp else None
            if server.has_extn("starttls"):
                server.starttls(context=ssl._create_unverified_context())
                server.ehlo()
            server.login(username, password)
            return self._result(
                host,
                port,
                username,
                password,
                AttemptStatus.SUCCESS,
                banner=banner,
                response_time=time.monotonic() - started,
            )
        except smtplib.SMTPAuthenticationError as exc:
            return self._result(
                host, port, username, password, AttemptStatus.FAILED, error=str(exc)
            )
        except smtplib.SMTPException as exc:
            return self._result(host, port, username, password, AttemptStatus.ERROR, error=str(exc))
        except TimeoutError as exc:
            return self._result(
                host, port, username, password, AttemptStatus.TIMEOUT, error=str(exc)
            )
        except OSError as exc:
            return self._result(host, port, username, password, AttemptStatus.ERROR, error=str(exc))
        finally:
            if server is not None:
                with contextlib.suppress(OSError):
                    server.close()


__all__ = ["SMTPAttacker"]
