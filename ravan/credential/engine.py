"""Brute engine — drives credential attempts against one service, safely.

Bounded concurrency, per-user lockout tracking (skips accounts nearing a real
lockout), stop-on-success per user, and optional per-attempt delay/jitter. This
lockout-awareness is what separates a responsible engagement tool from a blunt
brute-forcer.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field

from ravan.credential.attempt import AttemptResult, AttemptStatus
from ravan.credential.base import ProtocolAttacker
from ravan.credential.lockout import LockoutDetector


@dataclass
class BruteConfig:
    timeout: float = 5.0
    workers: int = 8
    delay: float = 0.0  # base per-attempt delay in seconds
    jitter: float = 0.0  # random extra delay in [0, jitter)
    stop_on_success: bool = True
    lockout_threshold: int = 5
    lockout_window: float = 300.0
    max_attempts: int | None = None


@dataclass
class BruteOutcome:
    host: str
    port: int
    protocol: str
    attempts: int = 0
    found: list[AttemptResult] = field(default_factory=list)
    lockouts: list[AttemptResult] = field(default_factory=list)
    errors: int = 0
    skipped: int = 0
    unsupported: bool = False


class BruteEngine:
    def __init__(
        self,
        attacker: ProtocolAttacker,
        config: BruteConfig | None = None,
        *,
        on_result: Callable[[AttemptResult], None] | None = None,
    ) -> None:
        self.attacker = attacker
        self.config = config or BruteConfig()
        self._on_result = on_result

    def run(self, host: str, port: int, pairs: Iterable[tuple[str, str]]) -> BruteOutcome:
        outcome = BruteOutcome(host=host, port=port, protocol=self.attacker.protocol)
        if not self.attacker.available():
            outcome.unsupported = True
            return outcome

        cfg = self.config
        lockout = LockoutDetector(cfg.lockout_threshold, cfg.lockout_window)
        found_users: set[str] = set()
        pair_iter = iter(pairs)
        exhausted = False

        with ThreadPoolExecutor(max_workers=max(1, cfg.workers)) as pool:
            in_flight: dict[Future[AttemptResult], str] = {}
            while not exhausted or in_flight:
                while len(in_flight) < cfg.workers and not exhausted:
                    nxt = self._next_pair(pair_iter, host, found_users, lockout, outcome)
                    if nxt is None:
                        exhausted = True
                        break
                    user, password = nxt
                    outcome.attempts += 1
                    fut = pool.submit(self._attempt, host, port, user, password)
                    in_flight[fut] = user
                if not in_flight:
                    break
                done, _ = wait(in_flight.keys(), return_when=FIRST_COMPLETED)
                for fut in done:
                    user = in_flight.pop(fut)
                    self._handle(fut.result(), found_users, lockout, outcome)
        return outcome

    def _next_pair(
        self,
        pair_iter: Iterator[tuple[str, str]],
        host: str,
        found_users: set[str],
        lockout: LockoutDetector,
        outcome: BruteOutcome,
    ) -> tuple[str, str] | None:
        cfg = self.config
        for user, password in pair_iter:
            if cfg.max_attempts is not None and outcome.attempts >= cfg.max_attempts:
                return None
            if cfg.stop_on_success and user in found_users:
                outcome.skipped += 1
                continue
            if lockout.is_locked_out(host, user):
                outcome.skipped += 1
                continue
            return user, password
        return None

    def _attempt(self, host: str, port: int, user: str, password: str) -> AttemptResult:
        if self.config.delay or self.config.jitter:
            time.sleep(self.config.delay + random.random() * self.config.jitter)
        return self.attacker.authenticate(host, port, user, password, self.config.timeout)

    def _handle(
        self,
        result: AttemptResult,
        found_users: set[str],
        lockout: LockoutDetector,
        outcome: BruteOutcome,
    ) -> None:
        if self._on_result is not None:
            self._on_result(result)
        if result.valid:
            outcome.found.append(result)
            found_users.add(result.username)
            lockout.record_success(result.host, result.username)
        elif result.is_lockout:
            outcome.lockouts.append(result)
            lockout.record_failure(result.host, result.username)
        elif result.status is AttemptStatus.FAILED:
            lockout.record_failure(result.host, result.username)
        elif result.status in (AttemptStatus.ERROR, AttemptStatus.TIMEOUT):
            outcome.errors += 1


__all__ = ["BruteConfig", "BruteEngine", "BruteOutcome"]
