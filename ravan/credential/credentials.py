"""Credential providers — turn head options into an ordered stream of
``(username, password)`` pairs per attack mode.

Modes: dictionary (user-major), spray (password-major, lockout-safe ordering),
smart (username/company/year pattern generation), defaults (known default
credentials), combo (explicit user:pass pairs). Ported from
credential-attacks-toolkit's mutator/mode logic.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_DATA_DIR = Path(__file__).parent / "data"

MODES = ("dictionary", "spray", "smart", "defaults", "combo")

# Protocol name -> service key in default_creds.json.
_PROTOCOL_SERVICE = {"http-basic": "http", "http-form": "http"}


def load_smart_patterns() -> list[str]:
    data = json.loads((_DATA_DIR / "smart_patterns.json").read_text(encoding="utf-8"))
    return [str(p) for p in data] if isinstance(data, list) else []


def load_default_creds(service: str | None = None) -> list[tuple[str, str]]:
    data = json.loads((_DATA_DIR / "default_creds.json").read_text(encoding="utf-8"))
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for entry in data:
        if service and entry.get("service") != service:
            continue
        pair = (str(entry.get("username", "")), str(entry.get("password", "")))
        if pair not in seen:
            seen.add(pair)
            pairs.append(pair)
    return pairs


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def _read_file_lines(path: str) -> list[str]:
    p = Path(path)
    if not p.is_file():
        return []
    return [line.strip() for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


@dataclass
class CredentialSpec:
    """A resolved set of credentials to try, plus the mode that orders them."""

    mode: str = "dictionary"
    users: list[str] = field(default_factory=list)
    passwords: list[str] = field(default_factory=list)
    combos: list[tuple[str, str]] = field(default_factory=list)
    company: str = ""
    service: str = ""
    year: int = field(default_factory=lambda: datetime.now(UTC).year)
    max_pairs: int | None = None

    @classmethod
    def from_options(cls, options: Mapping[str, Any], protocol: str) -> CredentialSpec:
        users = _as_list(options.get("username")) + _as_list(options.get("users"))
        if options.get("users_file"):
            users += _read_file_lines(str(options["users_file"]))
        passwords = _as_list(options.get("password")) + _as_list(options.get("passwords"))
        if options.get("passwords_file"):
            passwords += _read_file_lines(str(options["passwords_file"]))

        combos: list[tuple[str, str]] = []
        for raw in _as_list(options.get("combo")):
            if ":" in raw:
                u, _, p = raw.partition(":")
                combos.append((u, p))
        if options.get("combo_file"):
            for raw in _read_file_lines(str(options["combo_file"])):
                if ":" in raw:
                    u, _, p = raw.partition(":")
                    combos.append((u, p))

        max_pairs = options.get("max_pairs")
        return cls(
            mode=str(options.get("mode", "dictionary")),
            users=_dedupe(users),
            passwords=_dedupe(passwords),
            combos=combos,
            company=str(options.get("company", "")),
            service=str(options.get("service") or _PROTOCOL_SERVICE.get(protocol, protocol)),
            max_pairs=int(max_pairs) if max_pairs else None,
        )

    def pairs(self) -> Iterator[tuple[str, str]]:
        stream = self._raw_pairs()
        if self.max_pairs is None:
            yield from stream
            return
        for index, pair in enumerate(stream):
            if index >= self.max_pairs:
                return
            yield pair

    def _raw_pairs(self) -> Iterator[tuple[str, str]]:
        if self.mode == "combo":
            yield from self.combos
        elif self.mode == "defaults":
            yield from load_default_creds(self.service)
        elif self.mode == "smart":
            yield from self._smart_pairs()
        elif self.mode == "spray":
            for password in self.passwords:  # password-major = lockout-safe order
                for user in self.users:
                    yield user, password
        else:  # dictionary (user-major)
            for user in self.users:
                for password in self.passwords:
                    yield user, password

    def _smart_pairs(self) -> Iterator[tuple[str, str]]:
        patterns = load_smart_patterns()
        seen: set[tuple[str, str]] = set()
        for user in self.users or [""]:
            for pattern in patterns:
                rendered = self._render(pattern, user)
                if rendered is None:
                    continue
                pair = (user, rendered)
                if pair not in seen:
                    seen.add(pair)
                    yield pair

    def _render(self, pattern: str, user: str) -> str | None:
        result = pattern
        subs = {
            "{username}": user.lower(),
            "{Username}": user.title(),
            "{USERNAME}": user.upper(),
            "{company}": self.company.lower(),
            "{Company}": self.company.title(),
            "{COMPANY}": self.company.upper(),
            "{YEAR}": str(self.year),
        }
        for placeholder, value in subs.items():
            result = result.replace(placeholder, value)
        # Drop patterns that still reference an unfilled placeholder.
        if "{" in result and "}" in result:
            return None
        return result or None


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


__all__ = ["MODES", "CredentialSpec", "load_default_creds", "load_smart_patterns"]
