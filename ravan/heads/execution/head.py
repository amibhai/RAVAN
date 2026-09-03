"""Execution head (Head #4) — benign command execution via native interpreters.

Runs lab-safe atomics that spawn real child processes (PowerShell, cmd, Unix
shell, Python, WMI) executing harmless canaries, generating the process-creation
telemetry defenders detect. MITRE ATT&CK Execution (T1059, T1047).
"""

from __future__ import annotations

from ravan.emulation.head import LocalAtomicHead
from ravan.heads.execution.atomics import EXECUTION_ATOMICS
from ravan.schemas.events import Tactic


class ExecutionHead(LocalAtomicHead):
    head_name = "execution"
    technique_id = "T1059"
    technique_name = "Command and Scripting Interpreter"
    tactic = Tactic.EXECUTION
    required_permissions = ("execute-emulation",)
    description = "Execution: benign command execution via native interpreters (T1059/T1047)."
    atomics = EXECUTION_ATOMICS


__all__ = ["ExecutionHead"]
