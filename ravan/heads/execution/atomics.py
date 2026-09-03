"""Execution atomics — benign command execution via native interpreters.

Each atomic spawns a real child process running a harmless canary (print a
marker, then a whoami/hostname discovery command an adversary typically runs
post-execution). That generates the process-creation telemetry — parent/child
lineage, command line — that endpoint sensors detect, with zero side effects.
"""

from __future__ import annotations

import sys
from typing import ClassVar

from ravan.emulation.atomic import Atomic, AtomicOutcome
from ravan.emulation.runner import AtomicEnv, run_command
from ravan.emulation.system import ALL_PLATFORMS, UNIX_PLATFORMS, Platform, which


class _InterpreterAtomic(Atomic):
    """Runs a benign canary through a specific interpreter."""

    executable: ClassVar[str] = ""

    def resolve_executable(self) -> str | None:
        return which(self.executable)

    def build_argv(self, executable: str, marker: str) -> list[str]:
        raise NotImplementedError

    def execute(self, env: AtomicEnv) -> AtomicOutcome:
        executable = self.resolve_executable()
        if executable is None:
            return AtomicOutcome.skipped(f"{self.executable!r} not found on PATH")
        result = run_command(self.build_argv(executable, env.marker), timeout=env.timeout)
        details = {"interpreter": self.executable, **result.to_details()}
        details["marker_echoed"] = env.marker in (result.stdout + result.stderr)
        if result.timed_out:
            return AtomicOutcome.failed("command timed out", **details)
        return AtomicOutcome.ok(**details)


class PythonExec(_InterpreterAtomic):
    technique_id = "T1059.006"
    technique_name = "Command and Scripting Interpreter: Python"
    name = "python"
    platforms = ALL_PLATFORMS

    def resolve_executable(self) -> str | None:
        return sys.executable  # the running interpreter is always present

    def build_argv(self, executable: str, marker: str) -> list[str]:
        code = (
            "import getpass, socket; "
            f"print({marker!r}); "
            "print('whoami:', getpass.getuser(), 'host:', socket.gethostname())"
        )
        return [executable, "-c", code]


class PowerShellExec(_InterpreterAtomic):
    technique_id = "T1059.001"
    technique_name = "Command and Scripting Interpreter: PowerShell"
    name = "powershell"
    platforms = frozenset({Platform.WINDOWS})
    executable = "powershell"

    def build_argv(self, executable: str, marker: str) -> list[str]:
        return [
            executable,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"Write-Output '{marker}'; whoami",
        ]


class CmdExec(_InterpreterAtomic):
    technique_id = "T1059.003"
    technique_name = "Command and Scripting Interpreter: Windows Command Shell"
    name = "cmd"
    platforms = frozenset({Platform.WINDOWS})
    executable = "cmd"

    def build_argv(self, executable: str, marker: str) -> list[str]:
        return [executable, "/c", f"echo {marker} & whoami"]


class ShellExec(_InterpreterAtomic):
    technique_id = "T1059.004"
    technique_name = "Command and Scripting Interpreter: Unix Shell"
    name = "sh"
    platforms = UNIX_PLATFORMS
    executable = "sh"

    def build_argv(self, executable: str, marker: str) -> list[str]:
        return [executable, "-c", f"echo {marker}; id -un; hostname"]


class WmiExec(Atomic):
    technique_id = "T1047"
    technique_name = "Windows Management Instrumentation"
    name = "wmi"
    platforms = frozenset({Platform.WINDOWS})

    def execute(self, env: AtomicEnv) -> AtomicOutcome:
        command = f"cmd /c echo {env.marker}"
        if which("wmic"):
            argv = ["wmic", "process", "call", "create", command]
        elif which("powershell"):
            argv = [
                "powershell",
                "-NoProfile",
                "-Command",
                "Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
                f"-Arguments @{{CommandLine='{command}'}}",
            ]
        else:
            return AtomicOutcome.skipped("neither wmic nor powershell available")
        result = run_command(argv, timeout=env.timeout)
        return AtomicOutcome.ok(mechanism="Win32_Process.Create", **result.to_details())


#: All execution atomics, in a stable order.
EXECUTION_ATOMICS: list[type[Atomic]] = [
    PythonExec,
    PowerShellExec,
    CmdExec,
    ShellExec,
    WmiExec,
]


__all__ = [
    "EXECUTION_ATOMICS",
    "CmdExec",
    "PowerShellExec",
    "PythonExec",
    "ShellExec",
    "WmiExec",
]
