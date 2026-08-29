"""Lockout-safety tracker — the differentiator over naive brute-forcers.

Tracks per-host/user failures in a sliding window so the engine can skip an
account that is close to a real lockout, rather than tripping it. Thread-safe.
Ported from credential-attacks-toolkit.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from collections.abc import Callable


class LockoutDetector:
    """Flag a host/user as at-risk once ``threshold`` failures occur within
    ``window`` seconds."""

    def __init__(
        self,
        threshold: int = 5,
        window: float = 300.0,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if threshold < 1:
            raise ValueError("threshold must be >= 1")
        self.threshold = threshold
        self.window = window
        self._clock = clock or time.monotonic
        self._data: defaultdict[str, defaultdict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self._lock = threading.Lock()

    def record_failure(self, host: str, user: str) -> None:
        with self._lock:
            self._data[host][user].append(self._clock())

    def record_success(self, host: str, user: str) -> None:
        with self._lock:
            self._data[host][user].clear()

    def is_locked_out(self, host: str, user: str) -> bool:
        cutoff = self._clock() - self.window
        with self._lock:
            recent = [t for t in self._data[host][user] if t >= cutoff]
            self._data[host][user] = recent
            return len(recent) >= self.threshold

    def failure_count(self, host: str, user: str) -> int:
        cutoff = self._clock() - self.window
        with self._lock:
            return sum(1 for t in self._data[host][user] if t >= cutoff)

    def reset(self) -> None:
        with self._lock:
            self._data.clear()


__all__ = ["LockoutDetector"]
