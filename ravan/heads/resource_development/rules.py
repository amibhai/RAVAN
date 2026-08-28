"""Hashcat rule-file export — turn the target's intelligence into a `.rule`
transformation usable against any base wordlist (rockyou, SecLists, ...) at
hashcat-native speed, plus a companion seeds file. Ported from wordsmith.

    cat seeds.txt rockyou.txt > combined.txt
    hashcat -a 0 -r target.rule combined.txt hash.txt

Rule syntax: https://hashcat.net/wiki/doku.php?id=rule_based_attack
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from ravan.heads.resource_development.profile import SeedProfile

_DATA_DIR = Path(__file__).parent / "data"

RULE_TIERS = ("basic", "standard", "exhaustive")
_TIER_CEILING: dict[str, int] = {"basic": 150, "standard": 1000, "exhaustive": 4000}


def _escape(ch: str) -> str:
    """Backslash-escape non-alphanumerics so they are always safe as literal
    arguments to a hashcat rule function."""
    return ch if ch.isalnum() else f"\\{ch}"


def _append_chain(suffix: str) -> str:
    """'24!' -> '$2$4$!' — one append token per character, left to right."""
    return "".join(f"${_escape(c)}" for c in suffix)


def _prepend_chain(prefix: str) -> str:
    """'Hi' -> '^i^H' — ^ pushes to the front, so build in reverse."""
    return "".join(f"^{_escape(c)}" for c in reversed(prefix))


def _sub_rule(src: str, dst: str) -> str | None:
    """'a','@' -> 'sa\\@' — single-char substitute-all only."""
    if len(src) != 1 or len(dst) != 1:
        return None
    return f"s{_escape(src)}{_escape(dst)}"


def _load_json(filename: str) -> dict[str, list[str]]:
    data = json.loads((_DATA_DIR / filename).read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


class RuleExporter:
    """Builds a hashcat-compatible ``.rule`` file (+ seeds) from a
    :class:`SeedProfile` and the shared data tables."""

    def __init__(self, profile: SeedProfile) -> None:
        self.profile = profile
        self._leet_map = _load_json("leet_map.json")
        self._suffixes = _load_json("suffixes.json")
        self._current_year = datetime.now(UTC).year

    @staticmethod
    def _case_rules() -> list[str]:
        return [":", "l", "u", "c", "C", "t"]

    def _leet_sub_rules(self) -> list[str]:
        rules: list[str] = []
        for src, subs in self._leet_map.items():
            for dst in subs:
                rule = _sub_rule(src, dst)
                if rule:
                    rules.append(rule)
        return rules

    def _suffix_strings(self, tier: str) -> list[str]:
        strings = list(self._suffixes.get("priority_suffixes", [])) + list(
            self._suffixes.get("symbols", [])
        )
        if tier in ("standard", "exhaustive"):
            strings += list(self._suffixes.get("common_endings", []))
        return list(dict.fromkeys(strings))

    def _year_strings(self, tier: str) -> list[str]:
        years: list[str] = []
        if self.profile.founded_year:
            years.append(self.profile.founded_year)
        span = 2 if tier == "basic" else 5
        years += [str(y) for y in range(self._current_year, self._current_year - span, -1)]
        out: list[str] = []
        for y in years:
            out.append(y)
            if len(y) >= 2:
                out.append(y[-2:])
        return list(dict.fromkeys(out))

    def build_rules(self, tier: str = "standard") -> list[str]:
        """Return the deduplicated, tier-capped list of hashcat rule lines."""
        if tier not in RULE_TIERS:
            raise ValueError(f"unknown rules tier {tier!r} (expected one of {RULE_TIERS})")

        lines: list[str] = list(self._case_rules())
        for case_op in ("", "c"):
            for suf in self._suffix_strings(tier):
                lines.append(f"{case_op}{_append_chain(suf)}")
        for pre in dict.fromkeys(self._suffixes.get("prepend_symbols", [])):
            lines.append(_prepend_chain(pre))

        if tier in ("standard", "exhaustive"):
            leet = self._leet_sub_rules()
            lines.extend(leet)
            lines.extend(f"c{r}" for r in leet)
            for yr in self._year_strings(tier):
                chain = _append_chain(yr)
                lines += [chain, f"c{chain}"]

        if tier == "exhaustive":
            for word in ("admin", "root", "pass", "password", "welcome", "test", "hello"):
                lines += [_append_chain(word), _prepend_chain(word)]

        deduped = list(dict.fromkeys(lines))
        return deduped[: _TIER_CEILING[tier]]

    def build_seeds(self) -> list[str]:
        """Target-specific words to concatenate with a base wordlist before the
        rule file is applied."""
        p = self.profile
        seeds: list[str] = []
        if p.name:
            seeds.append(p.name)
        if p.domain:
            seeds.append(p.domain_base())
        for emp in p.employees:
            seeds.extend(part for part in emp.split() if part)
        seeds.extend(p.products)
        if p.location:
            seeds.append(p.location)
        seeds.extend(p.keywords)
        seeds.extend(p.extra_words)

        seen: set[str] = set()
        out: list[str] = []
        for word in seeds:
            cleaned = word.strip()
            key = cleaned.lower()
            if cleaned and key not in seen:
                seen.add(key)
                out.append(cleaned)
        return out


__all__ = ["RULE_TIERS", "RuleExporter"]
