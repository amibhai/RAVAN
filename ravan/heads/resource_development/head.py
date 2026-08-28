"""Resource Development head (Head #2) — targeted credential-wordlist and
hashcat-rule generation.

Ports wordsmith's offline generation engine into RAVAN's plugin interface. A
target-tailored wordlist (and/or a hashcat rule transformation) is a developed
offensive capability, so this maps to MITRE ATT&CK T1587 (Develop Capabilities)
under the Resource Development tactic; the artifacts feed later Credential
Access (T1110) activity.

Seeds are supplied via head options (company, domain, employees, products,
location, founded_year, keywords, seeds); live OSINT collection is a later,
network-dependent upgrade. The engine is pure stdlib, deterministic, and
memory-bounded.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from ravan.core.base import BaseHead, RunContext
from ravan.heads.resource_development.mutator import (
    DEFAULT_MAX_SCAN,
    MutationEngine,
)
from ravan.heads.resource_development.profile import SeedProfile
from ravan.heads.resource_development.rules import RuleExporter
from ravan.schemas.events import HeadReport, Outcome, Tactic

DEVELOP_CAPABILITIES = "T1587"
DEFAULT_MAX_WORDS = 100_000


class ResourceDevelopmentHead(BaseHead):
    head_name = "resdev"
    technique_id = DEVELOP_CAPABILITIES
    technique_name = "Develop Capabilities"
    tactic = Tactic.RESOURCE_DEVELOPMENT
    required_permissions = ("wordlist-generation",)
    description = "Resource Development: OSINT-seeded wordlist + hashcat rule generation."

    def __init__(self) -> None:
        self._artifacts: list[str] = []
        self._candidates = 0
        self._rules = 0

    # -- lifecycle ------------------------------------------------------------

    def run(self, context: RunContext) -> None:
        profile = SeedProfile.from_options(context.options)

        # A wordlist is tailored to a target: if a domain is named, it must be
        # in scope. authorize() logs a BLOCKED event and raises if it isn't.
        if profile.domain:
            context.authorize(profile.domain)

        target = profile.domain or (f"org:{profile.name}" if profile.name else "unspecified-target")

        base_words = profile.base_words()
        if not base_words:
            context.record(
                target=target,
                outcome=Outcome.FAIL,
                details={
                    "reason": "no seed words — supply company/domain/keywords/seeds options",
                },
            )
            return

        output_dir = self._output_dir(context)
        stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        slug = _slug(profile.label())

        rules_only = bool(context.option("rules_only", False))
        export_rules = bool(context.option("export_rules", False)) or rules_only

        if not rules_only:
            self._generate_wordlist(context, profile, base_words, output_dir, slug, stamp, target)
        if export_rules:
            self._export_rules(context, profile, output_dir, slug, stamp, target)

    def report(self) -> HeadReport:
        summary = (
            f"resdev: developed {len(self._artifacts)} artifact(s): "
            f"{self._candidates} wordlist candidate(s), {self._rules} hashcat rule(s)"
        )
        return self.build_report(summary=summary)

    def cleanup(self) -> None:
        self._artifacts.clear()
        self._candidates = 0
        self._rules = 0

    # -- wordlist generation --------------------------------------------------

    def _generate_wordlist(
        self,
        context: RunContext,
        profile: SeedProfile,
        base_words: list[str],
        output_dir: Path,
        slug: str,
        stamp: str,
        target: str,
    ) -> None:
        engine = MutationEngine(profile)
        strategies = context.option("strategies")
        if isinstance(strategies, (list, tuple)) and strategies:
            engine.enable_strategies(int(n) for n in strategies)

        max_words = int(context.option("max_words", DEFAULT_MAX_WORDS))
        max_scan = int(context.option("max_scan", DEFAULT_MAX_SCAN))
        candidates = engine.mutate_all(base_words, max_words=max_words, max_scan=max_scan or None)
        self._candidates = len(candidates)

        output_dir.mkdir(parents=True, exist_ok=True)
        words = [w for w, _ in candidates]
        full_path = output_dir / f"resdev_{slug}_{stamp}_full.txt"
        top_path = output_dir / f"resdev_{slug}_{stamp}_top1000.txt"
        _write_lines(full_path, words)
        _write_lines(top_path, words[:1000])
        artifacts = {"full": str(full_path), "top1000": str(top_path)}

        name_tokens = {
            part.lower()
            for emp in profile.employees
            for part in emp.split()
            if len(part) > 1
        }
        if name_tokens:
            names = [w for w in words if any(tok in w.lower() for tok in name_tokens)]
            names_path = output_dir / f"resdev_{slug}_{stamp}_names.txt"
            _write_lines(names_path, names)
            artifacts["names"] = str(names_path)

        self._artifacts.extend(artifacts.values())
        context.record(
            target=target,
            outcome=Outcome.SUCCESS,
            details={
                "artifact": "wordlist",
                "seed_words": len(base_words),
                "candidates_kept": len(candidates),
                "candidates_scanned": engine.scanned,
                "strategies": sorted(engine.stats),
                "top_samples": [{"word": w, "score": s} for w, s in candidates[:5]],
                "outputs": artifacts,
            },
        )

    # -- hashcat rules --------------------------------------------------------

    def _export_rules(
        self,
        context: RunContext,
        profile: SeedProfile,
        output_dir: Path,
        slug: str,
        stamp: str,
        target: str,
    ) -> None:
        tier = str(context.option("rules_tier", "standard"))
        exporter = RuleExporter(profile)
        try:
            rules = exporter.build_rules(tier)
        except ValueError as exc:
            context.record(
                target=target,
                outcome=Outcome.FAIL,
                details={"artifact": "hashcat-rules", "reason": str(exc)},
            )
            return
        seeds = exporter.build_seeds()
        self._rules = len(rules)

        output_dir.mkdir(parents=True, exist_ok=True)
        rule_path = output_dir / f"resdev_{slug}_{stamp}.rule"
        seeds_path = output_dir / f"resdev_{slug}_{stamp}_seeds.txt"
        _write_lines(rule_path, rules)
        _write_lines(seeds_path, seeds)
        self._artifacts.extend([str(rule_path), str(seeds_path)])

        context.record(
            target=target,
            outcome=Outcome.SUCCESS,
            details={
                "artifact": "hashcat-rules",
                "tier": tier,
                "rules_count": len(rules),
                "seeds_count": len(seeds),
                "rule_file": str(rule_path),
                "seeds_file": str(seeds_path),
                "usage": f"cat {seeds_path.name} rockyou.txt > combined.txt && "
                f"hashcat -a 0 -r {rule_path.name} combined.txt hash.txt",
            },
        )

    # -- helpers --------------------------------------------------------------

    def _output_dir(self, context: RunContext) -> Path:
        configured = context.option("output_dir")
        if configured:
            return Path(str(configured))
        return Path("engagements") / "artifacts" / _slug(context.scope.name)


def _slug(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", text.strip())
    return cleaned.strip("_") or "target"


def _write_lines(path: Path, lines: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for line in lines:
            fh.write(line)
            fh.write("\n")


__all__: list[str] = ["ResourceDevelopmentHead"]
