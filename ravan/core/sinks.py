"""Event sinks: where :class:`TechniqueEvent` records are written.

A sink is any callable ``(TechniqueEvent) -> None``. The engine writes every
event it produces to its sink, so swapping storage (in-memory for tests, JSONL
for engagements, console for humans) needs no engine changes.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import IO, Protocol, runtime_checkable

from ravan.schemas.events import TechniqueEvent


@runtime_checkable
class EventSink(Protocol):
    """Anything that can consume a :class:`TechniqueEvent`."""

    def __call__(self, event: TechniqueEvent) -> None: ...


class ListSink:
    """Collects events in memory. Primarily for tests and embedding."""

    def __init__(self) -> None:
        self.events: list[TechniqueEvent] = []

    def __call__(self, event: TechniqueEvent) -> None:
        self.events.append(event)


class JsonlFileSink:
    """Appends one JSON object per line — the canonical engagement log format
    consumed by the Phase 5 detection-validation layer."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh: IO[str] = self.path.open("a", encoding="utf-8")

    def __call__(self, event: TechniqueEvent) -> None:
        self._fh.write(event.model_dump_json() + "\n")
        self._fh.flush()

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.close()

    def __enter__(self) -> JsonlFileSink:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class ConsoleSink:
    """Writes a compact, human-readable line per event (default: stderr)."""

    def __init__(self, stream: IO[str] | None = None) -> None:
        self.stream: IO[str] = stream if stream is not None else sys.stderr

    def __call__(self, event: TechniqueEvent) -> None:
        ts = event.timestamp.isoformat(timespec="seconds")
        line = (
            f"[{ts}] {event.outcome.value.upper():7} "
            f"{event.attack_id:<8} {event.tactic.value:<22} {event.target}"
        )
        print(line, file=self.stream)


class MultiSink:
    """Fans one event out to several sinks."""

    def __init__(self, *sinks: EventSink) -> None:
        self.sinks: tuple[EventSink, ...] = sinks

    def __call__(self, event: TechniqueEvent) -> None:
        for sink in self.sinks:
            sink(event)


__all__ = ["ConsoleSink", "EventSink", "JsonlFileSink", "ListSink", "MultiSink"]
