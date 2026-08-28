"""Banner-to-CVE matching (passive: compares a grabbed banner/version string
against known-vulnerable version regexes; performs no exploitation)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_DATA_DIR = Path(__file__).parent / "data"


@dataclass
class CVEEntry:
    cve_id: str
    service: str
    version_regex: str
    cvss_score: float
    severity: str
    description: str
    compiled: re.Pattern[str]
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def pattern(self) -> re.Pattern[str]:
        return self.compiled


_CVE_CACHE: list[CVEEntry] | None = None


def load_cve_db() -> list[CVEEntry]:
    """Load and cache the CVE database.

    Each ``version_regex`` is compiled at load time; entries with a malformed
    regex or missing required field are skipped, so matching never raises.
    """
    global _CVE_CACHE
    if _CVE_CACHE is None:
        raw = json.loads((_DATA_DIR / "cve_db.json").read_text(encoding="utf-8"))
        entries: list[CVEEntry] = []
        for item in raw:
            try:
                compiled = re.compile(item["version_regex"], re.IGNORECASE)
            except (KeyError, re.error):
                continue
            entries.append(
                CVEEntry(
                    cve_id=item.get("cve_id", "UNKNOWN"),
                    service=item.get("service", ""),
                    version_regex=item["version_regex"],
                    cvss_score=float(item.get("cvss_score", 0.0)),
                    severity=item.get("severity", "unknown"),
                    description=item.get("description", ""),
                    compiled=compiled,
                    remediation=item.get("remediation", ""),
                    references=list(item.get("references", [])),
                )
            )
        _CVE_CACHE = entries
    return _CVE_CACHE


def match_cves(
    banner: str,
    *,
    service: str = "",
    cve_db: list[CVEEntry] | None = None,
) -> list[CVEEntry]:
    """Return CVEs whose ``version_regex`` matches ``banner``, highest CVSS
    first.

    Matching is on the banner text, because the CVE ``service`` field names a
    product (``apache``) while a scanned port reports a protocol (``http``); the
    version regexes are product-specific enough to keep false positives low.
    ``service`` is accepted for future narrowing but is not used to filter.
    """
    if not banner:
        return []
    entries = cve_db if cve_db is not None else load_cve_db()
    matches = [entry for entry in entries if entry.pattern().search(banner)]
    matches.sort(key=lambda c: c.cvss_score, reverse=True)
    return matches


def to_details(entry: CVEEntry) -> dict[str, Any]:
    return {
        "cve_id": entry.cve_id,
        "service": entry.service,
        "cvss_score": entry.cvss_score,
        "severity": entry.severity,
        "description": entry.description,
        "remediation": entry.remediation,
    }


__all__ = ["CVEEntry", "load_cve_db", "match_cves", "to_details"]
