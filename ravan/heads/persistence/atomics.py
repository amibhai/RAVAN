"""Persistence atomics — create a benign autostart artifact, then remove it.

Every atomic uses a *user-level* mechanism (no admin required), points the
persistence at a harmless canary, and reverts itself idempotently. The value is
the artifact-creation telemetry (a Run-key write, a startup file, a service
unit) that defenders should detect — the artifacts themselves do nothing and are
cleaned up. File locations are overridable via options so tests never touch real
autostart paths.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import ClassVar

from ravan.emulation.atomic import Atomic, AtomicOutcome
from ravan.emulation.runner import AtomicEnv, run_command
from ravan.emulation.system import Platform


def _suffix(marker: str) -> str:
    return marker[-8:]


# --- file-based artifacts -----------------------------------------------------


class _FileArtifactAtomic(Atomic):
    """Base for atomics that persist by writing a single file."""

    mechanism: ClassVar[str] = ""

    def artifact_path(self, env: AtomicEnv) -> Path:
        raise NotImplementedError

    def content(self, env: AtomicEnv) -> str:
        raise NotImplementedError

    def execute(self, env: AtomicEnv) -> AtomicOutcome:
        path = self.artifact_path(env)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.content(env), encoding="utf-8")
        except OSError as exc:
            return AtomicOutcome.failed(str(exc), artifact=str(path))
        self._path = path
        return AtomicOutcome.ok(mechanism=self.mechanism, artifact=str(path), marker=env.marker)

    def revert(self, env: AtomicEnv) -> None:
        path = getattr(self, "_path", None)
        if path is not None:
            with contextlib.suppress(OSError):
                Path(path).unlink()


class StartupFolderAtomic(_FileArtifactAtomic):
    technique_id = "T1547.001"
    technique_name = "Boot or Logon Autostart Execution: Startup Folder"
    name = "startup-folder"
    platforms = frozenset({Platform.WINDOWS})
    mechanism = "Startup folder script"

    def artifact_path(self, env: AtomicEnv) -> Path:
        override = env.option("startup_dir")
        base = (
            Path(str(override))
            if override
            else Path(os.environ.get("APPDATA", Path.home()))
            / "Microsoft"
            / "Windows"
            / "Start Menu"
            / "Programs"
            / "Startup"
        )
        return base / f"ravan_{_suffix(env.marker)}.bat"

    def content(self, env: AtomicEnv) -> str:
        return f"@echo off\r\nrem RAVAN benign persistence test\r\necho {env.marker}\r\n"


class SystemdUserServiceAtomic(_FileArtifactAtomic):
    technique_id = "T1543.002"
    technique_name = "Create or Modify System Process: Systemd Service"
    name = "systemd-user-service"
    platforms = frozenset({Platform.LINUX})
    mechanism = "systemd user service unit"

    def artifact_path(self, env: AtomicEnv) -> Path:
        override = env.option("systemd_dir")
        base = Path(str(override)) if override else Path.home() / ".config" / "systemd" / "user"
        return base / f"ravan-{_suffix(env.marker)}.service"

    def content(self, env: AtomicEnv) -> str:
        return (
            f"[Unit]\nDescription=RAVAN benign persistence test {env.marker}\n\n"
            f"[Service]\nType=oneshot\nExecStart=/bin/echo {env.marker}\n\n"
            "[Install]\nWantedBy=default.target\n"
        )


class LaunchAgentAtomic(_FileArtifactAtomic):
    technique_id = "T1543.001"
    technique_name = "Create or Modify System Process: Launch Agent"
    name = "launch-agent"
    platforms = frozenset({Platform.DARWIN})
    mechanism = "LaunchAgent plist"

    def artifact_path(self, env: AtomicEnv) -> Path:
        override = env.option("launchagents_dir")
        base = Path(str(override)) if override else Path.home() / "Library" / "LaunchAgents"
        return base / f"com.ravan.test.{_suffix(env.marker)}.plist"

    def content(self, env: AtomicEnv) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0"><dict>\n'
            f"  <key>Label</key><string>com.ravan.test.{_suffix(env.marker)}</string>\n"
            "  <key>ProgramArguments</key>\n"
            f"  <array><string>/bin/echo</string><string>{env.marker}</string></array>\n"
            "  <key>RunAtLoad</key><true/>\n"
            "</dict></plist>\n"
        )


class ShellProfileAtomic(Atomic):
    technique_id = "T1546.004"
    technique_name = "Event Triggered Execution: Unix Shell Configuration Modification"
    name = "shell-profile"
    platforms = frozenset({Platform.LINUX, Platform.DARWIN})

    def profile_path(self, env: AtomicEnv) -> Path:
        override = env.option("profile_path")
        return Path(str(override)) if override else Path.home() / ".bashrc"

    def execute(self, env: AtomicEnv) -> AtomicOutcome:
        path = self.profile_path(env)
        block = f"\n# {env.marker} BEGIN\nexport RAVAN_TEST={env.marker}\n# {env.marker} END\n"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(block)
        except OSError as exc:
            return AtomicOutcome.failed(str(exc), artifact=str(path))
        self._path = path
        self._marker = env.marker
        return AtomicOutcome.ok(
            mechanism="shell profile append", artifact=str(path), marker=env.marker
        )

    def revert(self, env: AtomicEnv) -> None:
        path = getattr(self, "_path", None)
        marker = getattr(self, "_marker", None)
        if path is None or marker is None:
            return
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines(keepends=True)
        except OSError:
            return
        kept: list[str] = []
        skipping = False
        for line in lines:
            if f"{marker} BEGIN" in line:
                skipping = True
                continue
            if f"{marker} END" in line:
                skipping = False
                continue
            if not skipping:
                kept.append(line)
        with contextlib.suppress(OSError):
            Path(path).write_text("".join(kept), encoding="utf-8")


# --- command-based artifacts --------------------------------------------------


class RegistryRunKeyAtomic(Atomic):
    technique_id = "T1547.001"
    technique_name = "Boot or Logon Autostart Execution: Registry Run Keys"
    name = "registry-run-key"
    platforms = frozenset({Platform.WINDOWS})
    RUN_KEY: ClassVar[str] = r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

    def value_name(self, env: AtomicEnv) -> str:
        return f"RAVAN-{_suffix(env.marker)}"

    def add_argv(self, env: AtomicEnv) -> list[str]:
        return [
            "reg",
            "add",
            self.RUN_KEY,
            "/v",
            self.value_name(env),
            "/t",
            "REG_SZ",
            "/d",
            f"cmd /c echo {env.marker}",
            "/f",
        ]

    def delete_argv(self, env: AtomicEnv) -> list[str]:
        return ["reg", "delete", self.RUN_KEY, "/v", self.value_name(env), "/f"]

    def execute(self, env: AtomicEnv) -> AtomicOutcome:
        result = run_command(self.add_argv(env), timeout=env.timeout)
        if result.returncode == 0:
            self._created = True
            return AtomicOutcome.ok(
                mechanism="HKCU Run key",
                key=self.RUN_KEY,
                value=self.value_name(env),
                **result.to_details(),
            )
        return AtomicOutcome.failed(
            result.stderr.strip() or "reg add failed", **result.to_details()
        )

    def revert(self, env: AtomicEnv) -> None:
        if getattr(self, "_created", False):
            run_command(self.delete_argv(env), timeout=env.timeout)


class ScheduledTaskAtomic(Atomic):
    technique_id = "T1053.005"
    technique_name = "Scheduled Task/Job: Scheduled Task"
    name = "scheduled-task"
    platforms = frozenset({Platform.WINDOWS})

    def task_name(self, env: AtomicEnv) -> str:
        return f"RAVAN-{_suffix(env.marker)}"

    def create_argv(self, env: AtomicEnv) -> list[str]:
        return [
            "schtasks",
            "/create",
            "/tn",
            self.task_name(env),
            "/tr",
            f"cmd /c echo {env.marker}",
            "/sc",
            "onlogon",
            "/f",
        ]

    def delete_argv(self, env: AtomicEnv) -> list[str]:
        return ["schtasks", "/delete", "/tn", self.task_name(env), "/f"]

    def execute(self, env: AtomicEnv) -> AtomicOutcome:
        result = run_command(self.create_argv(env), timeout=env.timeout)
        if result.returncode == 0:
            self._created = True
            return AtomicOutcome.ok(
                mechanism="scheduled task",
                task=self.task_name(env),
                trigger="onlogon",
                **result.to_details(),
            )
        return AtomicOutcome.failed(
            result.stderr.strip() or "schtasks failed", **result.to_details()
        )

    def revert(self, env: AtomicEnv) -> None:
        if getattr(self, "_created", False):
            run_command(self.delete_argv(env), timeout=env.timeout)


PERSISTENCE_ATOMICS: list[type[Atomic]] = [
    RegistryRunKeyAtomic,
    StartupFolderAtomic,
    ScheduledTaskAtomic,
    SystemdUserServiceAtomic,
    ShellProfileAtomic,
    LaunchAgentAtomic,
]


__all__ = [
    "PERSISTENCE_ATOMICS",
    "LaunchAgentAtomic",
    "RegistryRunKeyAtomic",
    "ScheduledTaskAtomic",
    "ShellProfileAtomic",
    "StartupFolderAtomic",
    "SystemdUserServiceAtomic",
]
