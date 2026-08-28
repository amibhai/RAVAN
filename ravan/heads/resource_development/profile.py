"""Target seed profile — the OSINT-derived context a wordlist is tailored to.

In RAVAN, seeds are supplied via head options (or a seeds file) rather than
collected live; live OSINT collection is a later, network-dependent upgrade.
The offline mutation/scoring/rule engine is the differentiator and is fully
deterministic and testable.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable):
        return [str(v).strip() for v in value if str(v).strip()]
    return [str(value)]


@dataclass
class SeedProfile:
    """Everything known about a target that shapes its candidate passwords."""

    name: str = ""
    domain: str = ""
    employees: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)
    location: str = ""
    founded_year: str = ""
    keywords: list[str] = field(default_factory=list)
    extra_words: list[str] = field(default_factory=list)
    policy: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_options(cls, options: Mapping[str, Any]) -> SeedProfile:
        return cls(
            name=str(options.get("company") or options.get("name") or "").strip(),
            domain=str(options.get("domain") or "").strip(),
            employees=_as_list(options.get("employees")),
            products=_as_list(options.get("products")),
            location=str(options.get("location") or "").strip(),
            founded_year=str(options.get("founded_year") or "").strip(),
            keywords=_as_list(options.get("keywords")),
            extra_words=_as_list(options.get("seeds")),
            policy=dict(options.get("policy") or {}),
        )

    def domain_base(self) -> str:
        """The registrable label of the domain, e.g. ``acme`` from
        ``acme.co.uk``."""
        if not self.domain:
            return ""
        return self.domain.split(".")[0].lower()

    def label(self) -> str:
        """A human-facing identifier for the target this profile describes."""
        return self.domain or self.name or "unknown-target"

    def base_words(self) -> list[str]:
        """Deduplicated seed words fed into the mutation engine."""
        words: list[str] = []
        if self.name:
            words.append(self.name)
        base = self.domain_base()
        if base:
            words.append(base)
        words.extend(self.keywords)
        words.extend(self.products)
        if self.location:
            words.append(self.location)
        for emp in self.employees:
            words.extend(part for part in emp.split() if part)
        words.extend(self.extra_words)

        seen: set[str] = set()
        out: list[str] = []
        for word in words:
            cleaned = word.strip()
            key = cleaned.lower()
            if cleaned and key not in seen:
                seen.add(key)
                out.append(cleaned)
        return out


__all__ = ["SeedProfile"]
