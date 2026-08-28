"""HTTP service fingerprinting (pure stdlib ``http.client``).

Captures status, server/technology identification, page title, and the
target's security-header posture (which hardening headers are present vs.
missing) — a compact, defender-relevant view of an HTTP endpoint.
"""

from __future__ import annotations

import contextlib
import http.client
import re
import ssl
from typing import Any

# Response headers a hardened endpoint is expected to set.
SECURITY_HEADERS: tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)

# Cookie-name -> technology hints.
_COOKIE_TECH: dict[str, str] = {
    "phpsessid": "PHP",
    "jsessionid": "Java/JSP",
    "asp.net_sessionid": "ASP.NET",
    "wordpress_": "WordPress",
    "wp-settings": "WordPress",
    "laravel_session": "Laravel",
    "csrftoken": "Django",
    "_rails": "Ruby on Rails",
}

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def probe_http(
    host: str,
    port: int,
    *,
    timeout: float = 4.0,
    use_tls: bool = False,
    path: str = "/",
    server_hostname: str | None = None,
) -> dict[str, Any]:
    """Fetch ``path`` and fingerprint the HTTP endpoint. Returns ``{}`` if the
    endpoint does not answer HTTP."""
    conn: http.client.HTTPConnection
    try:
        if use_tls:
            conn = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=ssl._create_unverified_context()
            )
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        host_header = server_hostname or host
        conn.request("GET", path, headers={"Host": host_header, "User-Agent": "ravan-recon"})
        resp = conn.getresponse()
        body = resp.read(8192)
        headers = {k.lower(): v for k, v in resp.getheaders()}
    except (OSError, http.client.HTTPException):
        return {}
    finally:
        with contextlib.suppress(OSError):
            conn.close()

    result: dict[str, Any] = {
        "scheme": "https" if use_tls else "http",
        "status": resp.status,
    }
    if resp.reason:
        result["reason"] = resp.reason
    for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        if headers.get(header):
            result[header.replace("-", "_")] = headers[header]
    if resp.status in (301, 302, 303, 307, 308) and headers.get("location"):
        result["redirect"] = headers["location"]

    title = _extract_title(body)
    if title:
        result["title"] = title

    present = [h for h in SECURITY_HEADERS if h in headers]
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    result["security_headers_present"] = present
    result["security_headers_missing"] = missing

    tech = _tech_hints(headers)
    if tech:
        result["tech"] = tech

    return result


def _extract_title(body: bytes) -> str:
    text = body.decode("utf-8", errors="replace")
    m = _TITLE_RE.search(text)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120]


def _tech_hints(headers: dict[str, str]) -> list[str]:
    hints: list[str] = []
    server = headers.get("server", "")
    if server:
        hints.append(server)
    if headers.get("x-powered-by"):
        hints.append(headers["x-powered-by"])
    cookies = headers.get("set-cookie", "").lower()
    for marker, tech in _COOKIE_TECH.items():
        if marker in cookies and tech not in hints:
            hints.append(tech)
    return hints


__all__ = ["SECURITY_HEADERS", "probe_http"]
