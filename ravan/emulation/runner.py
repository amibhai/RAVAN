"""Benign command runner and canary helpers for emulation atomics.

Everything runs with an explicit argument vector — **never** ``shell=True`` —
so there is no shell-injection surface and the recorded command line is exactly
what executed. Captures the process telemetry (pid, exit code, output, timing)
that endpoint sensors key on.
"""

from __future__ import annotations

import re
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Prefix that makes every RAVAN-emitted artifact/marker obviously benign and
#: greppable in logs and on disk.
MARKER_PREFIX = "RAVAN-BENIGN"


@dataclass
class CommandResult:
    """Telemetry from one executed command."""

    argv: list[str]
    pid: int | None
    returncode: int | None
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def command_line(self) -> str:
        return subprocess.list2cmdline(self.argv)

    def to_details(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "command_line": self.command_line,
            "pid": self.pid,
            "exit_code": self.returncode,
        }
        if self.timed_out:
            out["timed_out"] = True
        text = (self.stdout or self.stderr).strip()
        if text:
            out["output"] = text[:400]
        return out


def marker() -> str:
    """A unique, obviously-benign canary token."""
    return f"{MARKER_PREFIX}-{uuid.uuid4().hex[:12]}"


def run_command(
    argv: list[str],
    *,
    timeout: float = 15.0,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Run ``argv`` with no shell, capturing its telemetry. Never raises for a
    non-zero exit or a timeout — those are reported in the result."""
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(cwd) if cwd else None,
            env=env,
        )
    except OSError as exc:
        return CommandResult(argv, None, None, "", str(exc), time.monotonic() - started)

    pid = proc.pid
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return CommandResult(argv, pid, proc.returncode, stdout, stderr, time.monotonic() - started)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        return CommandResult(
            argv, pid, proc.returncode, stdout, stderr, time.monotonic() - started, timed_out=True
        )


def slug(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", text.strip())
    return cleaned.strip("_") or "engagement"


def staging_dir(scope_name: str, base: str | Path = "engagements/artifacts") -> Path:
    """A per-engagement working directory for emulation artifacts."""
    path = Path(base) / slug(scope_name) / "emulation"
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass
class AtomicEnv:
    """Everything an atomic needs to act, supplied by its head."""

    marker: str
    staging: Path
    timeout: float = 15.0
    options: dict[str, Any] = field(default_factory=dict)

    def option(self, key: str, default: Any = None) -> Any:
        return self.options.get(key, default)


__all__ = [
    "MARKER_PREFIX",
    "AtomicEnv",
    "CommandResult",
    "marker",
    "run_command",
    "slug",
    "staging_dir",
]
