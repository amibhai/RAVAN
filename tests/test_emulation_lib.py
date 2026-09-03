"""Tests for the shared ravan.emulation library."""

from __future__ import annotations

import sys
from pathlib import Path

from ravan.emulation import (
    Platform,
    current_platform,
    marker,
    resolve_local_target,
    run_command,
    staging_dir,
    which,
)
from ravan.emulation.runner import MARKER_PREFIX, CommandResult

from conftest import make_scope


def test_marker_is_unique_and_benign() -> None:
    a, b = marker(), marker()
    assert a != b
    assert a.startswith(MARKER_PREFIX)


def test_current_platform_and_which() -> None:
    assert current_platform() in set(Platform)
    assert which("this-tool-does-not-exist-xyz") is None


def test_run_command_captures_telemetry() -> None:
    result = run_command([sys.executable, "-c", "print('hi from ravan')"])
    assert result.returncode == 0
    assert "hi from ravan" in result.stdout
    assert result.pid is not None
    details = result.to_details()
    assert "command_line" in details and details["exit_code"] == 0


def test_run_command_missing_executable_is_reported_not_raised() -> None:
    result = run_command(["definitely-not-a-real-binary-xyz", "--nope"])
    assert result.returncode is None
    assert result.pid is None
    assert result.stderr  # the OSError message


def test_run_command_timeout() -> None:
    result = run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5)
    assert result.timed_out is True


def test_staging_dir_created(tmp_path: Path) -> None:
    path = staging_dir("Some Engagement!", base=tmp_path)
    assert path.is_dir()
    assert path == tmp_path / "Some_Engagement" / "emulation"


def test_command_result_to_details_truncates_output() -> None:
    result = CommandResult(["x"], 1, 0, "a" * 1000, "", 0.1)
    assert len(result.to_details()["output"]) <= 400


def test_resolve_local_target() -> None:
    in_scope = make_scope(scope={"targets": ["127.0.0.1"], "allowed_tactics": ["execution"]})
    assert resolve_local_target(in_scope) == "127.0.0.1"
    out = make_scope(scope={"targets": ["10.0.0.0/24"], "allowed_tactics": ["execution"]})
    assert resolve_local_target(out) is None
