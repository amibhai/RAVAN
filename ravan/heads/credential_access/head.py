"""Credential Access head (Head #6) — lockout-aware credential brute-forcing.

Ports credential-attacks-toolkit into RAVAN's plugin interface via the shared
``ravan.credential`` library. Drives dictionary / spray / smart / defaults /
combo attacks against in-scope services and emits scope-gated, ATT&CK-tagged
events (MITRE T1110, Brute Force). Nine protocols work with zero dependencies;
SSH additionally needs paramiko and degrades gracefully when absent.
"""

from __future__ import annotations

import ipaddress

from ravan.core.base import BaseHead, RunContext
from ravan.core.exceptions import ScopeViolation
from ravan.credential import (
    BruteConfig,
    BruteEngine,
    BruteOutcome,
    CredentialSpec,
    get_attacker,
)
from ravan.credential.protocols import PROTOCOLS, default_port
from ravan.schemas.events import HeadReport, Outcome, Tactic

# Attack mode -> (ATT&CK id, technique name) for the emitted event.
MODE_TECHNIQUE: dict[str, tuple[str, str]] = {
    "spray": ("T1110.003", "Brute Force: Password Spraying"),
    "dictionary": ("T1110.001", "Brute Force: Password Guessing"),
    "combo": ("T1110.004", "Brute Force: Credential Stuffing"),
    "smart": ("T1110.001", "Brute Force: Password Guessing"),
    "defaults": ("T1110.001", "Brute Force: Password Guessing"),
}


class CredentialAccessHead(BaseHead):
    head_name = "credaccess"
    technique_id = "T1110"
    technique_name = "Brute Force"
    tactic = Tactic.CREDENTIAL_ACCESS
    required_permissions = ("credential-attack",)
    description = "Credential Access: lockout-aware brute-force (dictionary/spray/smart/defaults)."

    def __init__(self) -> None:
        self._found = 0
        self._hosts = 0
        self._attempts = 0
        self._lockouts = 0

    # -- lifecycle ------------------------------------------------------------

    def run(self, context: RunContext) -> None:
        protocol = str(context.option("protocol", "")).strip().lower()
        if protocol not in PROTOCOLS:
            context.record(
                target=f"engagement:{context.scope.name}",
                outcome=Outcome.FAIL,
                details={
                    "reason": (
                        "unknown or missing 'protocol' option; "
                        f"choose one of {sorted(PROTOCOLS)}"
                    )
                },
            )
            return

        attacker = get_attacker(protocol, dict(context.options))
        if not attacker.available():
            context.record(
                target=f"engagement:{context.scope.name}",
                outcome=Outcome.FAIL,
                details={
                    "reason": (
                        f"protocol {protocol!r} backend unavailable "
                        "(missing optional dependency)"
                    )
                },
            )
            return

        port = int(context.option("port", 0)) or default_port(protocol)
        mode = str(context.option("mode", "dictionary")).lower()
        cfg = self._brute_config(context)

        for host in self._hosts_in_scope(context):
            try:
                context.authorize(host)
            except ScopeViolation:
                continue
            spec = CredentialSpec.from_options(context.options, protocol)
            engine = BruteEngine(attacker, cfg)
            outcome = engine.run(host, port, spec.pairs())
            self._emit_outcome(context, host, port, protocol, mode, outcome)

    def report(self) -> HeadReport:
        summary = (
            f"credaccess: {self._found} credential(s) found across {self._hosts} host(s), "
            f"{self._attempts} attempt(s), {self._lockouts} lockout signal(s)"
        )
        return self.build_report(summary=summary)

    def cleanup(self) -> None:
        self._found = self._hosts = self._attempts = self._lockouts = 0

    # -- helpers --------------------------------------------------------------

    def _brute_config(self, context: RunContext) -> BruteConfig:
        return BruteConfig(
            timeout=float(context.option("timeout", 5.0)),
            workers=int(context.option("workers", 8)),
            delay=float(context.option("delay", 0.0)),
            jitter=float(context.option("jitter", 0.0)),
            stop_on_success=bool(context.option("stop_on_success", True)),
            lockout_threshold=int(context.option("lockout_threshold", 5)),
            lockout_window=float(context.option("lockout_window", 300.0)),
            max_attempts=(
                int(context.option("max_attempts")) if context.option("max_attempts") else None
            ),
        )

    def _hosts_in_scope(self, context: RunContext) -> list[str]:
        explicit = context.option("hosts")
        if isinstance(explicit, (list, tuple)) and explicit:
            return [str(h) for h in explicit]
        # Otherwise use the engagement's scope targets, skipping whole networks
        # (brute-forcing every host in a CIDR is out of scope for this head).
        hosts: list[str] = []
        for target in context.targets:
            if "/" in target:
                try:
                    ipaddress.ip_network(target, strict=False)
                    continue  # a CIDR — skip
                except ValueError:
                    pass
            hosts.append(target)
        return hosts

    def _emit_outcome(
        self,
        context: RunContext,
        host: str,
        port: int,
        protocol: str,
        mode: str,
        outcome: BruteOutcome,
    ) -> None:
        attack_id, technique_name = MODE_TECHNIQUE.get(mode, MODE_TECHNIQUE["dictionary"])
        self._hosts += 1
        self._attempts += outcome.attempts

        for result in outcome.found:
            self._found += 1
            context.record(
                target=f"{host}:{port}",
                outcome=Outcome.SUCCESS,
                details={"mode": mode, **result.redacted()},
                attack_id=attack_id,
                technique_name=technique_name,
            )

        locked_users = {r.username for r in outcome.lockouts}
        for user in locked_users:
            self._lockouts += 1
            context.record(
                target=f"{host}:{port}",
                outcome=Outcome.BLOCKED,
                details={
                    "reason": "service signalled account lockout / rate limit",
                    "protocol": protocol,
                    "username": user,
                    "mode": mode,
                },
                attack_id=attack_id,
                technique_name=technique_name,
            )

        if not outcome.found and outcome.attempts:
            # Document the brute-force campaign even when nothing was found —
            # a failed-login storm is exactly what a defender should detect.
            context.record(
                target=f"{host}:{port}",
                outcome=Outcome.FAIL,
                details={
                    "mode": mode,
                    "protocol": protocol,
                    "attempts": outcome.attempts,
                    "errors": outcome.errors,
                },
                attack_id=attack_id,
                technique_name=technique_name,
            )
