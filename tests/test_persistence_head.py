"""Tests for the Persistence head (Head #5)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ravan.core.engine import Engine
from ravan.core.loader import StaticLoader
from ravan.core.sinks import ListSink
from ravan.emulation.runner import AtomicEnv, CommandResult
from ravan.emulation.system import Platform, current_platform
from ravan.heads.persistence import atomics as persistence_atomics
from ravan.heads.persistence.head import PersistenceHead
from ravan.schemas.events import Outcome

from conftest import IN_WINDOW, clock_at, make_scope


def _engine(scope, sink) -> Engine:
    return Engine(
        scope,
        sink=sink,
        loader=StaticLoader({"persistence": PersistenceHead}),
        clock=clock_at(IN_WINDOW),
    )


def _scope(**over):
    base = {
        "targets": ["127.0.0.1", "localhost"],
        "allowed_tactics": ["persistence"],
        "permissions": ["persistence-emulation"],
    }
    base.update(over)
    return make_scope(scope=base)


def _file_atomic_for_platform(tmp_path: Path) -> tuple[str, dict[str, str]]:
    """A file-based persistence atomic applicable on this OS, pointed at tmp."""
    if current_platform() is Platform.WINDOWS:
        return "startup-folder", {"startup_dir": str(tmp_path)}
    return "shell-profile", {"profile_path": str(tmp_path / "profile")}


def _first_artifact(events):
    for e in events:
        if e.outcome is Outcome.SUCCESS and e.details.get("artifact"):
            return e.details["artifact"], e.details["marker"]
    raise AssertionError("no artifact event")


def test_persistence_creates_then_reverts(tmp_path: Path) -> None:
    name, opts = _file_atomic_for_platform(tmp_path)
    result = _engine(_scope(), ListSink()).run_head(
        "persistence", options={"atomics": [name], **opts}
    )
    assert result.status == "ok"
    artifact, mrk = _first_artifact(result.events)
    # cleanup ran after the head: the marker must be gone (file deleted, or the
    # appended block stripped).
    path = Path(artifact)
    assert not path.exists() or mrk not in path.read_text(encoding="utf-8")


def test_persistence_keep_leaves_artifact(tmp_path: Path) -> None:
    name, opts = _file_atomic_for_platform(tmp_path)
    result = _engine(_scope(), ListSink()).run_head(
        "persistence", options={"atomics": [name], "keep": True, **opts}
    )
    artifact, mrk = _first_artifact(result.events)
    path = Path(artifact)
    assert path.exists() and mrk in path.read_text(encoding="utf-8")
    # a note documents what remains
    assert any(e.details.get("artifacts_kept") for e in result.events)


def test_persistence_requires_local_authorization(tmp_path: Path) -> None:
    scope = _scope(targets=["10.10.0.0/24"])
    result = _engine(scope, ListSink()).run_head(
        "persistence", options={"atomics": ["startup-folder"]}
    )
    assert any(e.outcome is Outcome.BLOCKED for e in result.events)
    assert not any(
        e.attack_id.startswith("T15") and e.outcome is Outcome.SUCCESS for e in result.events
    )


def test_registry_run_key_commands_and_revert(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kw: object) -> CommandResult:
        calls.append(argv)
        return CommandResult(argv, 4321, 0, "", "", 0.0)

    monkeypatch.setattr(persistence_atomics, "run_command", fake_run)
    env = AtomicEnv(marker="RAVAN-BENIGN-abcdef123456", staging=tmp_path)
    atomic = persistence_atomics.RegistryRunKeyAtomic()

    add = atomic.add_argv(env)
    assert add[:2] == ["reg", "add"]
    assert add[2] == persistence_atomics.RegistryRunKeyAtomic.RUN_KEY

    outcome = atomic.execute(env)
    assert outcome.status.value == "success"
    atomic.revert(env)
    assert any(c[:2] == ["reg", "delete"] for c in calls)
