"""TCP connect scanning and service/version detection (pure stdlib, no root).

Everything here uses ordinary TCP connect sockets — no raw sockets, no scapy,
no elevated privileges — so it runs identically on Windows, Linux, and macOS.
This is a deliberate portability trade-off against stealth SYN scanning, which
the recon head can gain later behind an optional dependency.
"""

from __future__ import annotations

import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_DATA_DIR = Path(__file__).parent / "data"


@dataclass
class PortResult:
    """State of a single scanned TCP port."""

    port: int
    state: str  # "open" | "closed" | "filtered"
    service: str = ""
    version: str = ""
    banner: str = ""

    def to_details(self) -> dict[str, Any]:
        out: dict[str, Any] = {"port": self.port, "state": self.state}
        if self.service:
            out["service"] = self.service
        if self.version:
            out["version"] = self.version
        if self.banner:
            out["banner"] = self.banner[:200]
        return out


@dataclass
class ServiceProbe:
    """One entry from service_probes.json."""

    service: str
    ports: list[int]
    probe: str = ""
    match: str | None = None
    _compiled: re.Pattern[str] | None = field(default=None, repr=False)

    def pattern(self) -> re.Pattern[str] | None:
        if self.match and self._compiled is None:
            try:
                self._compiled = re.compile(self.match)
            except re.error:
                self._compiled = None
        return self._compiled


_PROBES_CACHE: list[ServiceProbe] | None = None


def load_service_probes() -> list[ServiceProbe]:
    """Load and cache the TCP service-detection probes."""
    global _PROBES_CACHE
    if _PROBES_CACHE is None:
        raw = json.loads((_DATA_DIR / "service_probes.json").read_text(encoding="utf-8"))
        _PROBES_CACHE = [
            ServiceProbe(
                service=item["service"],
                ports=list(item.get("ports", [])),
                probe=item.get("probe", ""),
                match=item.get("match"),
            )
            for item in raw
        ]
    return _PROBES_CACHE


def scan_port(host: str, port: int, timeout: float = 1.5) -> str:
    """Return ``"open"``, ``"closed"``, or ``"filtered"`` for one TCP port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except TimeoutError:
        return "filtered"
    except OSError as exc:
        msg = str(exc)
        if "unreachable" in msg.lower() or "no route" in msg.lower():
            return "filtered"
        return "closed"


def connect_scan(
    host: str,
    ports: list[int],
    *,
    timeout: float = 1.5,
    workers: int = 100,
) -> list[PortResult]:
    """TCP-connect scan ``host`` across ``ports``. Returns open ports only,
    sorted by port number."""
    open_ports: list[PortResult] = []
    if not ports:
        return open_ports
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(ports)))) as pool:
        futures = {pool.submit(scan_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            port = futures[fut]
            if fut.result() == "open":
                open_ports.append(PortResult(port=port, state="open"))
    open_ports.sort(key=lambda r: r.port)
    return open_ports


def host_is_up(host: str, *, probe_ports: list[int], timeout: float = 1.0) -> int | None:
    """Return the first responsive port (open OR closed — both prove the host
    answered), or ``None`` if every probe timed out/was unreachable."""
    for port in probe_ports:
        if scan_port(host, port, timeout) in ("open", "closed"):
            return port
    return None


def detect_service(
    host: str,
    port: int,
    *,
    timeout: float = 2.0,
    probes: list[ServiceProbe] | None = None,
) -> tuple[str, str, str]:
    """Identify the service on an open port. Returns ``(service, version,
    banner)``; any field may be empty when detection is inconclusive.

    Tries port-matched probes first, then a passive banner grab, then a generic
    HTTP request — so services on non-standard ports are still identified.
    """
    probe_set = probes if probes is not None else load_service_probes()

    for probe in probe_set:
        if port not in probe.ports:
            continue
        service, version, banner = _run_probe(host, port, probe, timeout)
        if banner or service:
            return service, version, banner

    # Fallback 1: passive banner grab (SSH/FTP/SMTP/... announce themselves).
    banner = _grab_banner(host, port, b"", timeout)
    # Fallback 2: generic HTTP request (catches HTTP on non-standard ports).
    if not banner:
        http_get = f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: ravan-recon\r\n\r\n"
        banner = _grab_banner(host, port, http_get.encode("latin-1"), timeout)

    service = _service_from_banner(banner) or _well_known_service(port)
    return service, _extract_version(banner), banner


def _service_from_banner(banner: str) -> str:
    if not banner:
        return ""
    lowered = banner.lower()
    if banner.startswith("SSH-"):
        return "ssh"
    if "http/" in lowered or "\r\nserver:" in lowered or lowered.startswith("server:"):
        return "http"
    if lowered.startswith("220") and "ftp" in lowered:
        return "ftp"
    if lowered.startswith("220"):
        return "smtp"
    if "mysql" in lowered:
        return "mysql"
    return ""


_WELL_KNOWN: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}


def _well_known_service(port: int) -> str:
    return _WELL_KNOWN.get(port, "")


def _run_probe(
    host: str, port: int, probe: ServiceProbe, timeout: float
) -> tuple[str, str, str]:
    payload = probe.probe.replace("{target}", host).encode("latin-1", errors="replace")
    banner = _grab_banner(host, port, payload, timeout)
    if not banner:
        return "", "", ""
    pattern = probe.pattern()
    if pattern is not None:
        m = pattern.search(banner)
        if m:
            version = m.groupdict().get("version") or ""
            return probe.service, version, banner[:300]
        # Port matched but banner didn't — not this service.
        return "", "", banner[:300]
    return probe.service, "", banner[:300]


def _grab_banner(host: str, port: int, payload: bytes, timeout: float) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if payload:
                sock.sendall(payload)
            data = sock.recv(4096)
        return data.decode("utf-8", errors="replace").strip()[:300]
    except OSError:
        return ""


_SERVER_HEADER_RE = re.compile(r"Server:\s*([^\r\n]+)", re.IGNORECASE)
_VERSION_PATTERNS = [
    re.compile(r"([A-Za-z][\w.+-]*/\d+\.\d[\w.]*)"),  # e.g. Apache/2.4.49
    re.compile(r"version\s+(\S+)", re.IGNORECASE),
    re.compile(r"(\d+\.\d+[.\d]*(?:[-_]\w+)?)"),
]


def _extract_version(banner: str) -> str:
    """Extract a meaningful product/version string from a banner, preferring an
    HTTP ``Server:`` header or an ``SSH-`` identifier over a bare version."""
    if not banner:
        return ""
    m = _SERVER_HEADER_RE.search(banner)
    if m:
        return m.group(1).strip()[:80]
    if banner.startswith("SSH-"):
        return banner.split("\r")[0].split("\n")[0].strip()[:80]
    for pattern in _VERSION_PATTERNS:
        m = pattern.search(banner)
        if m:
            return m.group(1)
    return ""


__all__ = [
    "PortResult",
    "ServiceProbe",
    "connect_scan",
    "detect_service",
    "host_is_up",
    "load_service_probes",
    "scan_port",
]
