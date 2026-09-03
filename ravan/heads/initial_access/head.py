"""Initial Access head (Head #3) — the two dominant real-world entry vectors.

Per Verizon's DBIR, valid-account abuse (T1078) and public-facing exploitation
(T1190) lead initial access; phishing (T1566) remains pervasive. This head
emulates the two that are lab-safe and distinct from other heads:

  valid-accounts  T1078   confirm a credential grants a foothold on an
                          external-facing, in-scope service (via ravan.credential)
  phishing-lure   T1566   generate benign lure artifacts (macro/HTA/script/HTML)
                          for testing mail and endpoint controls — no delivery,
                          benign content, clearly marked

It performs no exploitation; T1190 endpoint identification lives in the recon head.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from pathlib import Path

from ravan.core.base import BaseHead, RunContext
from ravan.core.exceptions import ScopeViolation
from ravan.credential.protocols import PROTOCOLS, default_port, get_attacker
from ravan.emulation.runner import marker, staging_dir
from ravan.schemas.events import HeadReport, Outcome, Tactic

# lure type -> (extension, ATT&CK id, content renderer). Content is deliberately
# benign (marker only, no shell/download primitives) so it is safe to write in a
# test/CI environment without tripping local AV.
LURE_TEMPLATES: dict[str, tuple[str, str, Callable[[str], str]]] = {
    "vba-macro": (
        ".vba",
        "T1566.001",
        lambda m: (
            f'\' RAVAN benign phishing-lure test\nSub AutoOpen()\n  Debug.Print "{m}"\nEnd Sub\n'
        ),
    ),
    "hta": (
        ".hta",
        "T1566.001",
        lambda m: (
            "<html><head><title>RAVAN test</title></head>\n"
            f"<body>RAVAN benign lure {m}</body></html>\n"
        ),
    ),
    "script-js": (
        ".js",
        "T1566.001",
        lambda m: f"// RAVAN benign phishing-lure test\nWScript.Echo({m!r});\n",
    ),
    "html": (
        ".html",
        "T1566.002",
        lambda m: (
            f"<!doctype html><html><body><!-- RAVAN benign lure {m} -->"
            "<form>sign in</form></body></html>\n"
        ),
    ),
}
DEFAULT_LURES = ("vba-macro", "hta", "script-js", "html")


class InitialAccessHead(BaseHead):
    head_name = "initaccess"
    technique_id = "T1078"
    technique_name = "Valid Accounts"
    tactic = Tactic.INITIAL_ACCESS
    required_permissions = ("initial-access",)
    description = "Initial Access: valid-account foothold (T1078) + benign phishing lures (T1566)."

    def __init__(self) -> None:
        self._footholds = 0
        self._lures = 0

    # -- lifecycle ------------------------------------------------------------

    def run(self, context: RunContext) -> None:
        operations = self._operations(context)
        if "valid-accounts" in operations:
            self._valid_accounts(context)
        if "phishing-lure" in operations:
            self._phishing_lures(context)

    def report(self) -> HeadReport:
        summary = (
            f"initaccess: {self._footholds} valid-account foothold(s), "
            f"{self._lures} phishing lure(s) generated"
        )
        return self.build_report(summary=summary)

    def cleanup(self) -> None:
        self._footholds = self._lures = 0

    # -- valid accounts (T1078) -----------------------------------------------

    def _valid_accounts(self, context: RunContext) -> None:
        protocol = str(context.option("protocol", "")).strip().lower()
        credentials = self._credentials(context)
        if protocol not in PROTOCOLS or not credentials:
            return  # valid-accounts not configured; phishing-lure may still run
        attacker = get_attacker(protocol, dict(context.options))
        if not attacker.available():
            context.record(
                target=f"engagement:{context.scope.name}",
                outcome=Outcome.FAIL,
                details={"reason": f"protocol {protocol!r} backend unavailable"},
            )
            return
        port = int(context.option("port", 0)) or default_port(protocol)
        timeout = float(context.option("timeout", 5.0))

        for host in self._hosts_in_scope(context):
            try:
                context.authorize(host)
            except ScopeViolation:
                continue
            for user, password in credentials:
                result = attacker.authenticate(host, port, user, password, timeout)
                if result.valid:
                    self._footholds += 1
                    context.record(
                        target=f"{host}:{port}",
                        outcome=Outcome.SUCCESS,
                        details={
                            "technique": "foothold via valid account",
                            "protocol": protocol,
                            "username": user,
                            "status": result.status.value,
                        },
                        attack_id="T1078",
                        technique_name="Valid Accounts",
                    )
                    break  # one confirmed foothold per host is enough

    # -- phishing lures (T1566) -----------------------------------------------

    def _phishing_lures(self, context: RunContext) -> None:
        selected = context.option("lure_types")
        types = (
            [str(t) for t in selected]
            if isinstance(selected, (list, tuple)) and selected
            else list(DEFAULT_LURES)
        )
        override = context.option("output_dir")
        out_dir = Path(str(override)) if override else staging_dir(context.scope.name) / "lures"
        out_dir.mkdir(parents=True, exist_ok=True)

        token = marker()
        for lure in types:
            template = LURE_TEMPLATES.get(lure)
            if template is None:
                continue
            extension, attack_id, render = template
            path = out_dir / f"lure_{attack_id}_{token[-8:]}{extension}"
            try:
                path.write_text(render(token), encoding="utf-8")
            except OSError as exc:
                context.record(
                    target=f"staging:{context.scope.name}",
                    outcome=Outcome.FAIL,
                    details={"lure_type": lure, "error": str(exc)},
                    attack_id=attack_id,
                    technique_name="Phishing",
                )
                continue
            self._lures += 1
            context.record(
                target=f"staging:{context.scope.name}",
                outcome=Outcome.SUCCESS,
                details={
                    "lure_type": lure,
                    "artifact": str(path),
                    "marker": token,
                    "note": "benign lure for detection testing; not delivered",
                },
                attack_id=attack_id,
                technique_name="Phishing",
            )

    # -- helpers --------------------------------------------------------------

    def _operations(self, context: RunContext) -> set[str]:
        raw = context.option("operations")
        if isinstance(raw, (list, tuple)) and raw:
            return {str(o) for o in raw}
        return {"valid-accounts", "phishing-lure"}

    def _credentials(self, context: RunContext) -> list[tuple[str, str]]:
        creds: list[tuple[str, str]] = []
        for item in _as_list(context.option("credentials")):
            if ":" in item:
                user, _, password = item.partition(":")
                creds.append((user, password))
        user = context.option("username")
        if user is not None:
            pw = context.option("password")
            creds.append((str(user), str(pw) if pw is not None else ""))
        return creds

    def _hosts_in_scope(self, context: RunContext) -> list[str]:
        explicit = context.option("hosts")
        if isinstance(explicit, (list, tuple)) and explicit:
            return [str(h) for h in explicit]
        hosts: list[str] = []
        for target in context.targets:
            if "/" in target:
                try:
                    ipaddress.ip_network(target, strict=False)
                    continue
                except ValueError:
                    pass
            hosts.append(target)
        return hosts


def _as_list(value: object) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [value]
    return []


__all__ = ["InitialAccessHead"]
