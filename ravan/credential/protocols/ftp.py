"""FTP credential attacker (stdlib ftplib)."""

from __future__ import annotations

import contextlib
import ftplib
import time

from ravan.credential.attempt import AttemptResult, AttemptStatus
from ravan.credential.base import ProtocolAttacker


class FTPAttacker(ProtocolAttacker):
    protocol = "ftp"
    default_port = 21

    def authenticate(
        self, host: str, port: int, username: str, password: str, timeout: float
    ) -> AttemptResult:
        started = time.monotonic()
        ftp = ftplib.FTP()
        try:
            ftp.connect(host, port, timeout=timeout)
            banner = ftp.getwelcome()
            ftp.login(username, password)
            elapsed = time.monotonic() - started
            return self._result(
                host,
                port,
                username,
                password,
                AttemptStatus.SUCCESS,
                banner=banner,
                response_time=elapsed,
            )
        except ftplib.error_perm as exc:
            msg = str(exc)
            status = AttemptStatus.LOCKOUT if msg[:3] == "421" else AttemptStatus.FAILED
            return self._result(host, port, username, password, status, error=msg)
        except ftplib.error_temp as exc:
            return self._result(
                host, port, username, password, AttemptStatus.LOCKOUT, error=str(exc)
            )
        except ftplib.all_errors as exc:
            # all_errors = (ftplib.Error, OSError, EOFError); TimeoutError is an OSError.
            status = AttemptStatus.TIMEOUT if isinstance(exc, TimeoutError) else AttemptStatus.ERROR
            return self._result(host, port, username, password, status, error=str(exc))
        finally:
            with contextlib.suppress(OSError):
                ftp.close()


__all__ = ["FTPAttacker"]
