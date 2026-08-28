"""DNS reconnaissance (pure stdlib).

Host/subdomain/reverse lookups go through the system resolver (so lab-internal
zones resolve correctly). Record enumeration (NS/MX/TXT/SOA/CNAME) uses a small
self-contained UDP DNS client so we get rich records without a ``dnspython``
dependency. AXFR zone transfers are deferred to an optional-dependency upgrade.
"""

from __future__ import annotations

import os
import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# DNS record type codes.
QTYPES: dict[str, int] = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}
_QTYPE_NAMES = {v: k for k, v in QTYPES.items()}

_DATA_DIR = Path(__file__).parent / "data"


def resolve_host(name: str, timeout: float = 3.0) -> list[str]:
    """Resolve A/AAAA addresses for ``name`` via the system resolver."""
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError):
        return []
    finally:
        socket.setdefaulttimeout(None)
    addresses: list[str] = []
    for info in infos:
        addr = str(info[4][0])
        if addr not in addresses:
            addresses.append(addr)
    return addresses


def reverse_dns(ip: str, timeout: float = 3.0) -> str | None:
    """PTR lookup for an IP address; ``None`` if it has no reverse record."""
    socket.setdefaulttimeout(timeout)
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(None)


def load_subdomain_wordlist() -> list[str]:
    text = (_DATA_DIR / "subdomains.txt").read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip()]


def brute_subdomains(
    domain: str,
    words: list[str],
    *,
    timeout: float = 2.0,
    workers: int = 50,
) -> list[tuple[str, list[str]]]:
    """Resolve ``<word>.<domain>`` for each word; return the ones that exist
    with their addresses."""
    found: list[tuple[str, list[str]]] = []

    def _try(word: str) -> tuple[str, list[str]]:
        fqdn = f"{word}.{domain}"
        return fqdn, resolve_host(fqdn, timeout)

    if not words:
        return found
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(words)))) as pool:
        futures = [pool.submit(_try, w) for w in words]
        for fut in as_completed(futures):
            fqdn, addrs = fut.result()
            if addrs:
                found.append((fqdn, addrs))
    found.sort(key=lambda t: t[0])
    return found


def system_resolver() -> str | None:
    """Best-effort discovery of a usable recursive resolver.

    Reads ``/etc/resolv.conf`` on POSIX. On platforms where that is absent
    (e.g. Windows), returns ``None`` and record enumeration is skipped unless a
    resolver is supplied explicitly.
    """
    resolv = Path("/etc/resolv.conf")
    if resolv.is_file():
        try:
            for line in resolv.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
        except OSError:
            pass
    env = os.environ.get("RAVAN_DNS_RESOLVER")
    return env or None


def query(
    name: str,
    rtype: str,
    resolver: str,
    *,
    timeout: float = 3.0,
) -> list[str]:
    """Query ``resolver`` for ``name``'s ``rtype`` records over UDP.

    Returns record data as strings (addresses, hostnames, TXT text, ``pref
    host`` for MX). Returns ``[]`` on any error or empty answer.
    """
    qtype = QTYPES.get(rtype.upper())
    if qtype is None:
        return []

    query_id = 0x1337
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    packet = header + _encode_name(name) + struct.pack(">HH", qtype, 1)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (resolver, 53))
            data, _ = sock.recvfrom(4096)
    except OSError:
        return []

    return _parse_answers(data, qtype)


# -- DNS wire format helpers -------------------------------------------------


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("idna") if label else b""
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    next_offset = offset
    steps = 0
    while steps < 128:
        steps += 1
        if offset >= len(data):
            break
        length = data[offset]
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        if length == 0:
            offset += 1
            break
        labels.append(data[offset + 1 : offset + 1 + length].decode("latin-1"))
        offset += 1 + length
    if not jumped:
        next_offset = offset
    return ".".join(labels), next_offset


def _parse_answers(data: bytes, want_type: int) -> list[str]:
    if len(data) < 12:
        return []
    qd, an = struct.unpack(">HH", data[4:8])
    offset = 12
    for _ in range(qd):  # skip question section
        _, offset = _decode_name(data, offset)
        offset += 4
    results: list[str] = []
    for _ in range(an):
        _, offset = _decode_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlength]
        if rtype == want_type:
            decoded = _decode_rdata(rtype, rdata, data, offset)
            if decoded:
                results.append(decoded)
        offset += rdlength
    return results


def _decode_rdata(rtype: int, rdata: bytes, full: bytes, offset: int) -> str:
    if rtype == QTYPES["A"] and len(rdata) == 4:
        return socket.inet_ntoa(rdata)
    if rtype == QTYPES["AAAA"] and len(rdata) == 16:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if rtype in (QTYPES["NS"], QTYPES["CNAME"], QTYPES["PTR"]):
        name, _ = _decode_name(full, offset)
        return name
    if rtype == QTYPES["MX"] and len(rdata) >= 3:
        (pref,) = struct.unpack(">H", rdata[:2])
        host, _ = _decode_name(full, offset + 2)
        return f"{pref} {host}"
    if rtype == QTYPES["TXT"]:
        parts: list[str] = []
        i = 0
        while i < len(rdata):
            chunk = rdata[i + 1 : i + 1 + rdata[i]]
            parts.append(chunk.decode("utf-8", errors="replace"))
            i += 1 + rdata[i]
        return "".join(parts)
    if rtype == QTYPES["SOA"]:
        mname, off2 = _decode_name(full, offset)
        rname, _ = _decode_name(full, off2)
        return f"{mname} {rname}"
    return ""


def enumerate_records(
    domain: str,
    resolver: str,
    *,
    types: tuple[str, ...] = ("A", "AAAA", "NS", "MX", "TXT", "SOA"),
    timeout: float = 3.0,
) -> dict[str, list[str]]:
    """Query several record types for ``domain``. Empty types are omitted."""
    records: dict[str, list[str]] = {}
    for rtype in types:
        answers = query(domain, rtype, resolver, timeout=timeout)
        if answers:
            records[rtype] = answers
    return records


__all__ = [
    "QTYPES",
    "brute_subdomains",
    "enumerate_records",
    "load_subdomain_wordlist",
    "query",
    "resolve_host",
    "reverse_dns",
    "system_resolver",
]
