"""Lateral Movement head (Head #7) — credential reuse across the network.

Given credentials (from options, or discovered by the Credential Access head),
this maps their blast radius: which OTHER in-scope hosts and services accept the
same credential. Reusing a valid account to reach a new machine is the essence
of lateral movement (MITRE T1021 Remote Services, enabled by T1078 Valid
Accounts). Reuses the shared ``ravan.credential`` protocol attackers.
"""

from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from ravan.core.base import BaseHead, RunContext
from ravan.core.exceptions import ScopeViolation
from ravan.credential import AttemptResult, get_attacker
from ravan.credential.base import ProtocolAttacker
from ravan.credential.protocols import PROTOCOLS, default_port
from ravan.schemas.events import HeadReport, Outcome, Tactic

# Protocol -> (ATT&CK id, technique name). Remote Services has sub-techniques
# only for some protocols; the rest use the base T1021.
LM_SUBTECH: dict[str, tuple[str, str]] = {
    "ssh": ("T1021.004", "Remote Services: SSH"),
    "rdp": ("T1021.001", "Remote Services: Remote Desktop Protocol"),
    "vnc": ("T1021.005", "Remote Services: VNC"),
    "smb": ("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    "winrm": ("T1021.006", "Remote Services: Windows Remote Management"),
}


@dataclass
class _Task:
    host: str
    protocol: str
    port: int


class LateralMovementHead(BaseHead):
    head_name = "lateral"
    technique_id = "T1021"
    technique_name = "Remote Services"
    tactic = Tactic.LATERAL_MOVEMENT
    required_permissions = ("lateral-movement",)
    description = "Lateral Movement: validate credential reuse across in-scope hosts (T1021/T1078)."

    def __init__(self) -> None:
        self._reachable = 0
        self._tasks = 0

    # -- lifecycle ------------------------------------------------------------

    def run(self, context: RunContext) -> None:
        credentials = self._credentials(context)
        if not credentials:
            context.record(
                target=f"engagement:{context.scope.name}",
                outcome=Outcome.FAIL,
                details={
                    "reason": (
                        "no credentials supplied "
                        "(set 'credentials', 'username'/'password', or 'creds_file')"
                    )
                },
            )
            return

        protocols = self._protocols(context)
        if not protocols:
            context.record(
                target=f"engagement:{context.scope.name}",
                outcome=Outcome.FAIL,
                details={"reason": "no usable protocols (SSH needs paramiko; set 'protocols')"},
            )
            return

        tasks = self._build_tasks(context, protocols)
        timeout = float(context.option("timeout", 5.0))
        workers = int(context.option("workers", 16))

        attackers = {p: get_attacker(p, dict(context.options)) for p in protocols}

        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = {
                pool.submit(self._probe, attackers[t.protocol], t, credentials, timeout): t
                for t in tasks
            }
            for future in as_completed(futures):
                result = future.result()
                if result is not None and result.valid:
                    self._emit_access(context, futures[future], result)

    def report(self) -> HeadReport:
        summary = (
            f"lateral: credential reuse granted access on {self._reachable} "
            f"host/service pair(s) out of {self._tasks} probed"
        )
        return self.build_report(summary=summary)

    def cleanup(self) -> None:
        self._reachable = self._tasks = 0

    # -- credential / target resolution ---------------------------------------

    def _credentials(self, context: RunContext) -> list[tuple[str, str]]:
        creds: list[tuple[str, str]] = []
        raw = context.option("credentials")
        if isinstance(raw, (list, tuple)):
            for item in raw:
                text = str(item)
                if ":" in text:
                    user, _, pw = text.partition(":")
                    creds.append((user, pw))
        user = context.option("username")
        pw = context.option("password")
        if user is not None:
            creds.append((str(user), str(pw) if pw is not None else ""))
        creds_file = context.option("creds_file")
        if creds_file:
            path = Path(str(creds_file))
            if path.is_file():
                for line in path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if ":" in line:
                        u, _, p = line.partition(":")
                        creds.append((u, p))
        # De-duplicate, preserving order.
        seen: set[tuple[str, str]] = set()
        unique: list[tuple[str, str]] = []
        for cred in creds:
            if cred not in seen:
                seen.add(cred)
                unique.append(cred)
        return unique

    def _protocols(self, context: RunContext) -> list[str]:
        raw = context.option("protocols")
        if isinstance(raw, (list, tuple)) and raw:
            requested = [str(p).lower() for p in raw]
        elif isinstance(raw, str) and raw:
            requested = [p.strip().lower() for p in raw.split(",") if p.strip()]
        else:
            requested = ["ssh"]
        usable: list[str] = []
        for name in requested:
            cls = PROTOCOLS.get(name)
            if cls is not None and cls.available():
                usable.append(name)
        return usable

    def _build_tasks(self, context: RunContext, protocols: list[str]) -> list[_Task]:
        max_hosts = int(context.option("max_hosts", 256))
        ports = context.option("ports")
        port_map = ports if isinstance(ports, dict) else {}
        tasks: list[_Task] = []
        for target in context.targets:
            for host in _expand(target, max_hosts):
                try:
                    context.authorize(host)
                except ScopeViolation:
                    continue
                for protocol in protocols:
                    port = int(port_map.get(protocol, default_port(protocol)))
                    tasks.append(_Task(host=host, protocol=protocol, port=port))
        self._tasks = len(tasks)
        return tasks

    # -- probing --------------------------------------------------------------

    def _probe(
        self,
        attacker: ProtocolAttacker,
        task: _Task,
        credentials: list[tuple[str, str]],
        timeout: float,
    ) -> AttemptResult | None:
        for user, password in credentials:
            result = attacker.authenticate(task.host, task.port, user, password, timeout)
            if result.valid:
                return result
        return None

    def _emit_access(self, context: RunContext, task: _Task, result: AttemptResult) -> None:
        self._reachable += 1
        attack_id, technique_name = LM_SUBTECH.get(
            task.protocol, ("T1021", f"Remote Services: {task.protocol}")
        )
        context.record(
            target=f"{task.host}:{task.port}",
            outcome=Outcome.SUCCESS,
            details={
                "technique": "credential reuse (valid account)",
                "enabled_by": "T1078",
                **result.redacted(),
            },
            attack_id=attack_id,
            technique_name=technique_name,
        )


def _expand(target: str, max_hosts: int) -> list[str]:
    target = target.strip()
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return [target]
        hosts = network.hosts() if network.num_addresses > 2 else network
        out: list[str] = []
        for host in hosts:
            out.append(str(host))
            if len(out) >= max_hosts:
                break
        return out
    return [target]
