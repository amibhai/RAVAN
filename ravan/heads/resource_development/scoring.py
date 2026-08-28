"""Likelihood scoring — the single heuristic both the mutation engine (ranking
candidates into the bounded accumulator) and the final sort share, so the two
stages can never drift apart. Ported from wordsmith.
"""

from __future__ import annotations

import re
import string

from ravan.heads.resource_development.profile import SeedProfile

SCORE_WEIGHTS: dict[str, int] = {
    "target_name": 10,
    "employee_name": 8,
    "domain_name": 7,
    "product_name": 6,
    "year_suffix": 5,
    "symbol_end": 5,
    "region_pattern": 4,
    "location_name": 4,
    "length_sweet": 3,
    "mixed_charset": 3,
    "admin_keyword": 2,
    "keyboard_walk": 1,
    "too_long": -2,
    "all_lower": -5,
}

KEYBOARD_WALK_SEQS = (
    "qwerty", "asdfgh", "zxcvbn", "qweasd", "asdzxc",
    "1234", "12345", "123456", "654321",
)
ADMIN_KEYWORDS = frozenset({"admin", "pass", "password", "root", "user", "login", "default"})

_YEAR_SUFFIX_RE = re.compile(r"(19[89]\d|20[012]\d)$")
_REGION_PATTERN_RE = re.compile(r"[A-Z][a-z]+@(\d{4}|123|1234)$")


def score_word(word: str, profile: SeedProfile) -> int:
    """Heuristic likelihood score — higher means more plausible as a password
    for this specific target. Pure function of ``(word, profile)``."""
    score = 0
    wlow = word.lower()

    target_low = (profile.name or profile.domain_base()).lower()
    domain_low = profile.domain_base()
    employees = {e.lower() for e in profile.employees}
    products = {p.lower() for p in profile.products}
    location = profile.location.lower()

    if target_low and target_low in wlow:
        score += SCORE_WEIGHTS["target_name"]
    if domain_low and domain_low in wlow:
        score += SCORE_WEIGHTS["domain_name"]
    if any(emp and emp in wlow for emp in employees):
        score += SCORE_WEIGHTS["employee_name"]
    if any(prod and prod in wlow for prod in products):
        score += SCORE_WEIGHTS["product_name"]
    if location and location in wlow:
        score += SCORE_WEIGHTS["location_name"]

    if _YEAR_SUFFIX_RE.search(word):
        score += SCORE_WEIGHTS["year_suffix"]
    if word.endswith(("!", "@")):
        score += SCORE_WEIGHTS["symbol_end"]
    if _REGION_PATTERN_RE.search(word):
        score += SCORE_WEIGHTS["region_pattern"]
    if 8 <= len(word) <= 16:
        score += SCORE_WEIGHTS["length_sweet"]

    has_upper = any(c.isupper() for c in word)
    has_digit = any(c.isdigit() for c in word)
    has_special = any(c in string.punctuation for c in word)
    if sum([has_upper, any(c.islower() for c in word), has_digit, has_special]) >= 3:
        score += SCORE_WEIGHTS["mixed_charset"]

    if any(k in wlow for k in ADMIN_KEYWORDS):
        score += SCORE_WEIGHTS["admin_keyword"]
    if any(seq in wlow for seq in KEYBOARD_WALK_SEQS):
        score += SCORE_WEIGHTS["keyboard_walk"]
    if len(word) > 20:
        score += SCORE_WEIGHTS["too_long"]
    if word.islower() and not has_digit:
        score += SCORE_WEIGHTS["all_lower"]

    return score


__all__ = ["SCORE_WEIGHTS", "score_word"]
