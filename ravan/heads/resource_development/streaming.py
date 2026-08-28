"""Bounded top-K accumulator — the memory-safety backbone of the streaming
mutation pipeline (ported from wordsmith).

Holding every generated candidate in RAM before trimming does not scale: a
large target can produce tens of millions of live strings before any cap
applies. ``BoundedTopK`` keeps only the best ``capacity`` candidates seen so far
(by an externally supplied score) in a fixed-size min-heap, so peak memory is
O(capacity). A separate ``scan_ceiling`` bounds the dedup set, giving a
concrete, testable upper bound even for pathological seed lists.
"""

from __future__ import annotations

import heapq


class BoundedTopK:
    """Keep the best ``capacity`` distinct ``(word, score)`` offers seen so far.

    - Dedup: a word offered more than once counts once (first score wins).
    - Eviction: at capacity, a new offer displaces the lowest-scored kept word
      only if it scores strictly higher.
    - Scan ceiling: once ``scan_ceiling`` distinct words have been offered,
      ``offer()`` returns ``False`` and ``limit_hit`` is set; callers should
      stop feeding.
    """

    def __init__(self, capacity: int, scan_ceiling: int | None = None) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self.capacity = capacity
        self.scan_ceiling = scan_ceiling
        self._heap: list[tuple[int, int, str]] = []
        self._seen: set[str] = set()
        self._counter = 0
        self.limit_hit = False

    @property
    def scanned(self) -> int:
        return len(self._seen)

    @property
    def kept(self) -> int:
        return len(self._heap)

    def offer(self, word: str, score: int) -> bool:
        """Consider ``word``. Returns ``False`` once the scan ceiling is hit."""
        if word in self._seen:
            return not self.limit_hit
        if self.scan_ceiling is not None and len(self._seen) >= self.scan_ceiling:
            self.limit_hit = True
            return False

        self._seen.add(word)
        self._counter += 1
        entry = (score, self._counter, word)
        if len(self._heap) < self.capacity:
            heapq.heappush(self._heap, entry)
        elif entry > self._heap[0]:
            heapq.heapreplace(self._heap, entry)
        return not self.limit_hit

    def results(self) -> list[str]:
        """Kept words, best score first (ties broken by insertion order)."""
        return [w for _, _, w in sorted(self._heap, key=lambda e: (-e[0], e[1]))]

    def results_with_scores(self) -> list[tuple[str, int]]:
        return [(w, sc) for sc, _, w in sorted(self._heap, key=lambda e: (-e[0], e[1]))]

    def __len__(self) -> int:
        return self.kept


__all__ = ["BoundedTopK"]
