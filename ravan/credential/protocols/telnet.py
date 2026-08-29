"""Telnet credential attacker (raw socket; telnetlib was removed in 3.13).

Telnet login is unstructured, so this is a best-effort, prompt-driven attacker:
it waits for a login/password prompt, sends the credentials, and decides success
from the absence of a failure marker and a re-prompt. Prompts and the failure
marker are configurable per target.
"""

from __future__ import annotations

import contextlib
import socket
import time

from ravan.credential.attempt import AttemptResult, AttemptStatus
from ravan.credential.base import ProtocolAttacker

# Telnet IAC negotiation: refuse every DO/WILL so the server stops negotiating.
_IAC = 255


class TelnetAttacker(ProtocolAttacker):
    protocol = "telnet"
    default_port = 23

    def __init__(
        self,
        login_prompt: str = "login:",
        password_prompt: str = "password:",
        fail: str = "incorrect",
    ) -> None:
        self.login_prompt = login_prompt.lower()
        self.password_prompt = password_prompt.lower()
        self.fail = fail.lower()

    @classmethod
    def from_config(cls, config: dict[str, object]) -> TelnetAttacker:
        return cls(
            login_prompt=str(config.get("login_prompt", "login:")),
            password_prompt=str(config.get("password_prompt", "password:")),
            fail=str(config.get("fail", "incorrect")),
        )

    def authenticate(
        self, host: str, port: int, username: str, password: str, timeout: float
    ) -> AttemptResult:
        started = time.monotonic()
        sock: socket.socket | None = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(timeout)
            self._read_until(sock, self.login_prompt, timeout)
            sock.sendall(username.encode("latin-1", "replace") + b"\r\n")
            self._read_until(sock, self.password_prompt, timeout)
            sock.sendall(password.encode("latin-1", "replace") + b"\r\n")
            time.sleep(min(0.5, timeout))
            response = self._drain(sock).lower()
            elapsed = time.monotonic() - started
            if self.fail in response or self.login_prompt in response:
                return self._result(
                    host, port, username, password, AttemptStatus.FAILED, error="login rejected"
                )
            return self._result(
                host, port, username, password, AttemptStatus.SUCCESS, response_time=elapsed
            )
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

    def _read_until(self, sock: socket.socket, marker: str, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        buffer = b""
        while time.monotonic() < deadline:
            try:
                chunk = sock.recv(1024)
            except TimeoutError:
                break
            if not chunk:
                break
            buffer += _strip_iac(chunk)
            if marker in buffer.decode("latin-1", "replace").lower():
                break
        return buffer.decode("latin-1", "replace")

    def _drain(self, sock: socket.socket) -> str:
        try:
            return _strip_iac(sock.recv(4096)).decode("latin-1", "replace")
        except (TimeoutError, OSError):
            return ""


def _strip_iac(data: bytes) -> bytes:
    """Drop telnet IAC command triples so they don't pollute the text buffer."""
    if _IAC not in data:
        return data
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == _IAC and i + 2 < len(data):
            i += 3  # skip IAC + command + option
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


__all__ = ["TelnetAttacker"]
