"""Password-policy filtering — keep only candidates that satisfy a target's
password requirements. Applied inline during streaming so non-conforming
candidates never occupy an accumulator slot (ported from wordsmith).
"""

from __future__ import annotations

import string
from typing import Any

DEFAULT_POLICY: dict[str, Any] = {
    "min_length": 0,
    "max_length": 0,  # 0 == no limit
    "require_upper": False,
    "require_number": False,
    "require_special": False,
    "forbidden_chars": [],
}


def normalize_policy(policy: dict[str, Any] | None) -> dict[str, Any]:
    merged = dict(DEFAULT_POLICY)
    if policy:
        merged.update(policy)
    return merged


def passes_policy(word: str, policy: dict[str, Any]) -> bool:
    """True if ``word`` satisfies the (already-normalized) policy."""
    if not policy:
        return True

    min_len = int(policy.get("min_length", 0) or 0)
    max_len = int(policy.get("max_length", 0) or 0)
    if min_len and len(word) < min_len:
        return False
    if max_len and len(word) > max_len:
        return False
    if policy.get("require_upper") and not any(c.isupper() for c in word):
        return False
    if policy.get("require_number") and not any(c.isdigit() for c in word):
        return False
    if policy.get("require_special") and not any(c in string.punctuation for c in word):
        return False
    forbidden = set(policy.get("forbidden_chars") or [])
    return not (forbidden and any(c in forbidden for c in word))


__all__ = ["DEFAULT_POLICY", "normalize_policy", "passes_policy"]
