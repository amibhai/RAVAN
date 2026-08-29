"""Redis credential attacker (raw RESP over stdlib socket, no dependency)."""

from __future__ import annotations

import contextlib
import socket
import time

from ravan.credential.attempt import AttemptResult, AttemptStatus
from ravan.credential.base import ProtocolAttacker


def _resp_command(*args: str) -> bytes:
    out = [f"*{len(args)}\r\n".encode()]
    for arg in args:
        raw = arg.encode("utf-8")
        out.append(f"${len(raw)}\r\n".encode())
        out.append(raw + b"\r\n")
    return b"".join(out)


class RedisAttacker(ProtocolAttacker):
    protocol = "redis"
    default_port = 6379

    def authenticate(
        self, host: str, port: int, username: str, password: str, timeout: float
    ) -> AttemptResult:
        started = time.monotonic()
        # Redis default user is "default"; only send a 3-arg AUTH for ACL users.
        if username and username != "default":
            command = _resp_command("AUTH", username, password)
        else:
            command = _resp_command("AUTH", password)
        sock: socket.socket | None = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(timeout)
            sock.sendall(command)
            reply = sock.recv(512).decode("utf-8", "replace").strip()
            elapsed = time.monotonic() - started
            if reply.startswith("+OK"):
                return self._result(
                    host, port, username, password, AttemptStatus.SUCCESS, response_time=elapsed
                )
            if "no password is set" in reply.lower():
                # Server requires no auth — access is effectively open.
                return self._result(
                    host,
                    port,
                    username,
                    password,
                    AttemptStatus.NOAUTH,
                    error=reply,
                    response_time=elapsed,
                )
            return self._result(host, port, username, password, AttemptStatus.FAILED, error=reply)
        except TimeoutError as exc:
            return self._result(
                host, port, username, password, AttemptStatus.TIMEOUT, error=str(exc)
            )
        except OSError as exc:
            return self._result(host, port, username, password, AttemptStatus.ERROR, error=str(exc))
        finally:
            if sock is not None:
                with contextlib.suppress(OSError):
                    sock.close()


__all__ = ["RedisAttacker"]
