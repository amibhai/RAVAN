"""Port catalogs, port-spec parsing, and target classification for the recon
head.

The ``NMAP_TOP_1000`` list is frequency-ordered (most common service first), so
``top100`` means "the 100 most common services" — not "the 100 lowest port
numbers". Ported from SHIV recon-toolkit's curated nmap-services ordering.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

# Frequency-ordered TCP ports (deduped, order preserved). Truncate for top-N.
NMAP_TOP_1000: list[int] = list(
    dict.fromkeys(
        [
            80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
            1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113,
            81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
            26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
            631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000,
            513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128,
            444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
            6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000, 3001,
            5001, 82, 10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801, 5100, 7937,
            7938, 1434, 912, 914, 4111, 1058, 1059, 2967, 109, 220, 1074, 4125,
            6006, 2869, 1455, 9415, 8402, 6668, 6669, 1148, 2381, 4712,
            # Databases & NoSQL
            1521, 1522, 5433, 6379, 6380, 27017, 27018, 27019, 5984, 9200, 9300,
            11211, 28017, 50000,
            # DevOps / containers / cloud
            2375, 2376, 2377, 4243, 6443, 8001, 8002, 8005, 8006, 8010, 8020,
            8090, 8091, 8180, 8200, 8443, 8500, 8983, 9001, 9042, 9160, 9418,
            9444, 15672, 25672,
            # Windows / AD
            464, 593, 636, 3268, 3269, 5985, 5986, 9389, 47001,
            # Remote admin / mail / web extras
            5901, 5902, 2222, 22222, 2525, 3050, 5222, 5269, 5601, 5672, 7001,
            7443, 7474, 8161, 8888, 9091,
        ]
    )
)

# The smallest, highest-signal set — used when no port spec is given.
TOP_20: list[int] = NMAP_TOP_1000[:20]

# Ports that commonly speak TLS directly (used to decide TLS probing).
TLS_PORTS: frozenset[int] = frozenset(
    {443, 8443, 4443, 9443, 10443, 993, 995, 465, 587, 636, 3269, 989, 990, 5986}
)

# Ports that commonly speak plaintext HTTP (used to decide HTTP probing).
HTTP_PORTS: frozenset[int] = frozenset(
    {80, 81, 82, 8080, 8000, 8008, 8081, 8088, 8090, 8180, 8888, 3000, 5000, 9000, 9090}
)


def parse_port_spec(spec: str | int | Iterable[int]) -> list[int]:
    """Parse a port specification into a de-duplicated list of ports.

    Accepts an int, an iterable of ints, or a string: ``"top20"``,
    ``"top100"``, ``"top1000"``, ``"all"``, ``"80"``, ``"80,443"``,
    ``"1-1024"``, or a mix like ``"22,80,8000-8100"``.
    """
    if isinstance(spec, int):
        return [spec] if _valid_port(spec) else []
    if not isinstance(spec, str):
        return _dedupe(p for p in spec if _valid_port(p))

    text = spec.strip().lower()
    if text == "all":
        return list(range(1, 65536))
    if text == "top20":
        return list(TOP_20)
    if text == "top100":
        return NMAP_TOP_1000[:100]
    if text == "top1000":
        return list(NMAP_TOP_1000)

    ports: list[int] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, _, hi_s = part.partition("-")
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError:
                continue
            if lo > hi:
                lo, hi = hi, lo
            ports.extend(p for p in range(lo, hi + 1) if _valid_port(p))
        else:
            try:
                p = int(part)
            except ValueError:
                continue
            if _valid_port(p):
                ports.append(p)
    return _dedupe(ports)


def classify_target(target: str) -> str:
    """Classify a scope target as ``"cidr"``, ``"ip"``, or ``"host"``."""
    t = target.strip()
    if "/" in t:
        try:
            ipaddress.ip_network(t, strict=False)
            return "cidr"
        except ValueError:
            return "host"
    try:
        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        return "host"


def expand_hosts(target: str, max_hosts: int = 1024) -> list[str]:
    """Expand a target into concrete host addresses to scan.

    A CIDR becomes its usable host addresses (capped at ``max_hosts``); an IP or
    hostname passes through unchanged. The cap is a safety valve against
    accidentally expanding a huge range.
    """
    if classify_target(target) == "cidr":
        network = ipaddress.ip_network(target.strip(), strict=False)
        hosts = network.hosts() if network.num_addresses > 2 else network
        out: list[str] = []
        for host in hosts:
            out.append(str(host))
            if len(out) >= max_hosts:
                break
        return out
    return [target.strip()]


def _valid_port(port: int) -> bool:
    return 1 <= port <= 65535


def _dedupe(ports: Iterable[int]) -> list[int]:
    return list(dict.fromkeys(ports))


__all__ = [
    "HTTP_PORTS",
    "NMAP_TOP_1000",
    "TLS_PORTS",
    "TOP_20",
    "classify_target",
    "expand_hosts",
    "parse_port_spec",
]
