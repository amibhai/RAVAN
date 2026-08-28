"""Mutation engine — applies 13 strategies to seed words to generate scored,
policy-filtered password candidates, streaming through a bounded top-K
accumulator so peak memory stays O(capacity). Ported from wordsmith.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from ravan.heads.resource_development.policy import normalize_policy, passes_policy
from ravan.heads.resource_development.profile import SeedProfile
from ravan.heads.resource_development.scoring import score_word
from ravan.heads.resource_development.streaming import BoundedTopK

_DATA_DIR = Path(__file__).parent / "data"

DEFAULT_MAX_WORDS = 5_000_000
DEFAULT_MAX_SCAN = 20_000_000

STRATEGY_NAMES: dict[int, str] = {
    1: "case_variants",
    2: "leet_speak",
    3: "year_suffix",
    4: "symbol_append",
    5: "number_append",
    6: "word_combinator",
    7: "keyboard_walks",
    8: "name_variants",
    9: "domain_variants",
    10: "common_patterns",
    11: "cms_defaults",
    12: "temporal_patterns",
    13: "location_variants",
}

COMMON_STOP_WORDS = frozenset({
    "the", "and", "for", "with", "this", "that", "have", "from", "they", "will",
    "would", "could", "should", "about", "which", "their", "there", "what", "when",
    "where", "who", "how", "why", "all", "one", "two", "more", "also", "into", "than",
    "then", "your", "our", "its", "his", "her", "can", "are", "was", "were", "has",
    "had", "been", "being", "not", "but", "out", "any", "may", "other", "some", "just",
    "like", "get", "use", "new", "time", "long", "very", "even", "back", "only", "come",
    "over", "after", "these", "those", "both", "much", "many",
})


def _load_json(filename: str) -> object:
    return json.loads((_DATA_DIR / filename).read_text(encoding="utf-8"))


def _load_lines(filename: str) -> list[str]:
    text = (_DATA_DIR / filename).read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip()]


class MutationEngine:
    """Applies up to 13 configurable mutation strategies to seed words."""

    def __init__(self, profile: SeedProfile) -> None:
        self.profile = profile
        self.policy = normalize_policy(profile.policy)
        leet = _load_json("leet_map.json")
        suffixes = _load_json("suffixes.json")
        patterns = _load_json("patterns.json")
        self.leet_map: dict[str, list[str]] = leet if isinstance(leet, dict) else {}
        self.suffixes: dict[str, list[str]] = suffixes if isinstance(suffixes, dict) else {}
        self.patterns: list[str] = patterns if isinstance(patterns, list) else []
        self.keyboard_walks: list[str] = _load_lines("keyboard_walks.txt")
        self._current_year = datetime.now(UTC).year
        self._enabled: set[int] = set(range(1, 14))
        self.stats: dict[str, int] = {}
        self.scanned = 0

    def enable_strategies(self, nums: Iterable[int]) -> None:
        self._enabled = {n for n in nums if n in STRATEGY_NAMES}

    def mutate_all(
        self,
        words: list[str],
        max_words: int = DEFAULT_MAX_WORDS,
        max_scan: int | None = DEFAULT_MAX_SCAN,
    ) -> list[tuple[str, int]]:
        """Apply enabled strategies, returning kept ``(word, score)`` pairs
        sorted by score descending."""
        cleaned = [w.strip() for w in words if w.strip() and len(w.strip()) >= 2]
        if not cleaned:
            return []

        topk = BoundedTopK(
            capacity=max(1, max_words),
            scan_ceiling=max_scan if max_scan and max_scan > 0 else None,
        )
        self._offer_batch(topk, cleaned)

        per_word = {1, 2, 3, 4, 5, 7, 10, 11}
        for num in sorted(self._enabled):
            if topk.limit_hit:
                break
            name = STRATEGY_NAMES[num]
            try:
                generated = self._run_strategy(topk, num, cleaned, per_word)
                self.stats[name] = generated
            except Exception:  # one bad strategy must not sink the run
                self.stats[name] = 0

        if not topk.limit_hit:
            self._offer_batch(topk, _load_lines("common_passwords.txt"))

        self.scanned = topk.scanned
        return topk.results_with_scores()

    def _run_strategy(
        self, topk: BoundedTopK, num: int, cleaned: list[str], per_word: set[int]
    ) -> int:
        if num in per_word:
            fn = getattr(self, f"_s{num}")
            generated = 0
            for word in cleaned:
                variants = fn(word)
                generated += len(variants)
                if not self._offer_batch(topk, variants):
                    break
            return generated
        variants = self._run_aggregate_strategy(num, cleaned)
        self._offer_batch(topk, variants)
        return len(variants)

    def _run_aggregate_strategy(self, num: int, cleaned: list[str]) -> list[str]:
        if num == 6:
            return self._s6(cleaned)
        if num == 8:
            return self._s8(self.profile.employees)
        if num == 9:
            return self._s9(self.profile.domain)
        if num == 12:
            return self._s12()
        if num == 13:
            return self._s13(self.profile.location)
        return []

    def _offer_batch(self, topk: BoundedTopK, words: Iterable[str]) -> bool:
        for w in words:
            if not w or not passes_policy(w, self.policy):
                continue
            if not topk.offer(w, score_word(w, self.profile)):
                return False
        return True

    # -- strategies (ported from wordsmith) -----------------------------------

    def _s1(self, word: str) -> list[str]:
        alt = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word))
        variants = [word.lower(), word.upper(), word.title(), word.capitalize(), alt]
        if len(word) > 1:
            variants.append(word[0].lower() + word[1:].upper())
        return _unique(variants)

    def _s2(self, word: str) -> list[str]:
        results: list[str] = []
        wl = word.lower()
        for i, ch in enumerate(wl):
            for sub in self.leet_map.get(ch, []):
                new = wl[:i] + sub + wl[i + 1 :]
                results += [new, new.title()]
        vowel_map = {k: v[0] for k, v in self.leet_map.items() if k in "aeiou"}
        vowel_leet = "".join(vowel_map.get(c, c) for c in wl)
        if vowel_leet != wl:
            results += [vowel_leet, vowel_leet.title()]
        simple = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}
        s = "".join(simple.get(c, c) for c in wl)
        if s != wl:
            results += [s, s.title(), s.capitalize()]
        return _unique(results)[:50]

    def _s3(self, word: str) -> list[str]:
        results: list[str] = []
        base, title = word.lower(), word.title()
        years: list[str] = []
        if self.profile.founded_year:
            years.append(self.profile.founded_year)
        years += [str(y) for y in range(self._current_year, self._current_year - 5, -1)]
        for year in years:
            yr2 = year[-2:]
            results += [
                f"{base}{year}", f"{title}{year}", f"{base}{yr2}",
                f"{base}@{year}", f"{title}@{year}", f"{base}#{year}",
                f"{base}{year}!", f"{title}{year}!", f"{base}@{yr2}",
            ]
        for y in range(self._current_year - 30, self._current_year + 1):
            results += [f"{base}{y}", f"{title}{y}"]
        return _unique(results)

    def _s4(self, word: str) -> list[str]:
        base, title = word.lower(), word.title()
        results: list[str] = []
        for suf in self.suffixes.get("priority_suffixes", ["!", "@", "123", "!@#"]):
            results += [f"{base}{suf}", f"{title}{suf}"]
        for sym in self.suffixes.get("symbols", ["!", "@", "#"]):
            results += [f"{base}{sym}", f"{title}{sym}"]
        for pre in self.suffixes.get("prepend_symbols", ["!", "@"]):
            results.append(f"{pre}{base}")
        return _unique(results)

    def _s5(self, word: str) -> list[str]:
        base, title = word.lower(), word.title()
        results: list[str] = []
        for n in ["1", "12", "123", "1234", "12345", "01", "001", "007", "99", "00"]:
            results += [f"{base}{n}", f"{title}{n}"]
        results += [f"{base}{n}" for n in range(1, 100)]
        results += [f"{base}{n}" for n in (100, 111, 123, 321, 456, 789, 999, 1000, 1111, 2000)]
        return _unique(results)

    def _s6(self, words: list[str]) -> list[str]:
        results: list[str] = []
        top = [w.lower() for w in words if w.lower() not in COMMON_STOP_WORDS][:50]
        for i, w1 in enumerate(top):
            for w2 in top[i + 1 :]:
                results += [
                    f"{w1}{w2}", f"{w2}{w1}", f"{w1}_{w2}",
                    f"{w1.title()}{w2.title()}", f"{w1}{w2}!", f"{w1.title()}{w2}123",
                ]
        for w in top[:20]:
            for yr in range(self._current_year - 3, self._current_year + 1):
                results.append(f"{w}{yr}")
        return _unique(results)

    def _s7(self, word: str) -> list[str]:
        base = word.lower()
        walks = self.keyboard_walks or ["qwerty", "asdfgh", "zxcvbn"]
        results: list[str] = []
        for walk in walks[:20]:
            results += [f"{base}{walk}", f"{walk}{base}", f"{base}{walk[:6]}"]
        return _unique(results)

    def _s8(self, names: list[str]) -> list[str]:
        results: list[str] = []
        for name in names:
            parts = name.strip().split()
            if not parts:
                continue
            first = parts[0].lower()
            last = parts[-1].lower() if len(parts) > 1 else ""
            results += [first, first.title(), first.upper()]
            if last:
                results += [
                    last, last.title(), last.upper(),
                    f"{first}{last}", f"{first}.{last}", f"{first[0]}{last}",
                    f"{first[0]}.{last}", f"{first[0]}{last}".title(), f"{first}{last[0]}",
                ]
                for yr in range(self._current_year - 3, self._current_year + 1):
                    results += [
                        f"{first}{yr}", f"{first.title()}{yr}", f"{last}{yr}",
                        f"{first.title()}{yr}!", f"{first.title()}@{yr}",
                    ]
            for suf in ["123", "1234", "@123", "!", "@", "#1"]:
                results += [f"{first}{suf}", f"{first.title()}{suf}"]
        return _unique(results)

    def _s9(self, domain: str) -> list[str]:
        if not domain:
            return []
        base = domain.split(".")[0].lower() if "." in domain else domain.lower()
        results = [
            base, base.upper(), base.title(), f"{base}123", f"{base}1234",
            f"{base}!", f"{base}@", f"{base}admin", f"{base}user", f"{base}root",
            f"{base}pass", f"admin{base}", f"root{base}", f"{base}.com", f"@{base}.com",
        ]
        for yr in range(self._current_year - 5, self._current_year + 1):
            results += [f"{base}{yr}", f"{base.title()}{yr}", f"{base}@{yr}"]
        for suf in ["@123", "!@#", "#1", "123!", "@1234"]:
            results += [f"{base}{suf}", f"{base.title()}{suf}"]
        return _unique(results)

    def _s10(self, word: str) -> list[str]:
        year = str(self._current_year)
        subs = {
            "{word}": word.lower(), "{Word}": word.title(), "{WORD}": word.upper(),
            "{year}": year, "{yr2}": year[-2:], "{symbol}": "!",
        }
        results: list[str] = []
        for pattern in self.patterns:
            result = pattern
            for ph, val in subs.items():
                result = result.replace(ph, val)
            if result != pattern:
                results.append(result)
        return _unique(results)

    def _s11(self, word: str) -> list[str]:
        if word.lower() not in ("admin", "administrator", "root", "test"):
            return []
        results = [
            "admin", "administrator", "admin123", "admin@123", "Admin@123",
            "Admin123!", "root", "root123", "root@123", "default", "guest",
            "webmaster", "sysadmin", "netadmin", "dbadmin",
        ]
        base = self.profile.name.lower() or self.profile.domain_base()
        if base:
            for d in ("admin", "user", "root", "pass"):
                results += [f"{base}{d}", f"{d}{base}", f"{base}.{d}"]
        return _unique(results)

    def _s12(self) -> list[str]:
        years = [str(self._current_year), str(self._current_year - 1)]
        if self.profile.founded_year:
            years.append(self.profile.founded_year)
        months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        results: list[str] = []
        for yr in years:
            yr2 = yr[-2:]
            for m in months:
                results += [f"{m}{yr}", f"{m}{yr2}", f"{m.lower()}{yr}"]
            for q in ("Q1", "Q2", "Q3", "Q4"):
                results += [f"{q}{yr}", f"{q}FY{yr2}"]
            results += [f"FY{yr}", f"FY{yr2}", f"fy{yr2}"]
        return _unique(results)

    def _s13(self, location: str) -> list[str]:
        if not location:
            return []
        base = location.strip().lower()
        results = [
            base, base.title(), base.upper(), f"{base}123", f"{base}@123",
            f"{base}!", f"{base}@", f"{base}office", f"{base}hq",
            f"{base.title()}Office", f"{base.title()}HQ",
        ]
        for yr in range(self._current_year - 3, self._current_year + 1):
            results += [f"{base}{yr}", f"{base.title()}{yr}", f"{base}@{yr}"]
        return _unique(results)


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


__all__ = ["DEFAULT_MAX_SCAN", "DEFAULT_MAX_WORDS", "STRATEGY_NAMES", "MutationEngine"]
