"""Tests for the Resource Development head (Head #2) and its engine."""

from __future__ import annotations

from pathlib import Path

from ravan.core.engine import Engine
from ravan.core.loader import StaticLoader
from ravan.core.sinks import ListSink
from ravan.heads.resource_development.head import ResourceDevelopmentHead
from ravan.heads.resource_development.mutator import MutationEngine
from ravan.heads.resource_development.policy import passes_policy
from ravan.heads.resource_development.profile import SeedProfile
from ravan.heads.resource_development.rules import (
    RuleExporter,
    _append_chain,
    _prepend_chain,
    _sub_rule,
)
from ravan.heads.resource_development.scoring import score_word
from ravan.heads.resource_development.streaming import BoundedTopK

from conftest import IN_WINDOW, clock_at, make_scope


def _loader() -> StaticLoader:
    return StaticLoader({"resdev": ResourceDevelopmentHead})


# --- seed profile -------------------------------------------------------------


def test_seed_profile_base_words_dedupe() -> None:
    profile = SeedProfile(
        name="Acme",
        domain="acme.example.com",
        employees=["Rahul Sharma"],
        keywords=["acme", "widgets"],
    )
    words = profile.base_words()
    assert "Acme" in words
    assert profile.domain_base() == "acme"  # domain base derived
    assert "Rahul" in words and "Sharma" in words
    # case-insensitive dedupe keeps exactly one of the Acme/acme forms
    assert len([w for w in words if w.lower() == "acme"]) == 1


# --- bounded top-K ------------------------------------------------------------


def test_bounded_topk_keeps_highest_scores() -> None:
    topk = BoundedTopK(capacity=3)
    for word, score in [("a", 1), ("b", 5), ("c", 3), ("d", 4), ("e", 2)]:
        topk.offer(word, score)
    assert topk.results() == ["b", "d", "c"]  # top-3 by score
    assert topk.kept == 3


def test_bounded_topk_dedupes() -> None:
    topk = BoundedTopK(capacity=10)
    topk.offer("x", 5)
    topk.offer("x", 9)  # duplicate — ignored, first score wins
    assert topk.scanned == 1
    assert topk.results_with_scores() == [("x", 5)]


def test_bounded_topk_scan_ceiling() -> None:
    topk = BoundedTopK(capacity=100, scan_ceiling=2)
    assert topk.offer("a", 1) is True
    assert topk.offer("b", 1) is True
    assert topk.offer("c", 1) is False  # 3rd distinct word hits the ceiling
    assert topk.limit_hit is True
    assert topk.scanned == 2  # "c" was rejected before being counted


# --- scoring ------------------------------------------------------------------


def test_score_word_prefers_target_context() -> None:
    profile = SeedProfile(name="acme", domain="acme.com")
    on_target = score_word("Acme@2024", profile)
    generic = score_word("banana", profile)
    assert on_target > generic


# --- mutation -----------------------------------------------------------------


def test_mutation_generates_targeted_candidates() -> None:
    profile = SeedProfile(name="acme", domain="acme.com", founded_year="2011")
    engine = MutationEngine(profile)
    candidates = engine.mutate_all(profile.base_words(), max_words=500)
    words = {w for w, _ in candidates}
    assert len(candidates) <= 500
    assert any("acme" in w.lower() for w in words)
    # target-specific high-value candidates should surface near the top
    assert any(w.lower().startswith("acme") and w[-1] in "!@" for w in words)


def test_mutation_respects_max_words_cap() -> None:
    profile = SeedProfile(name="corporation", keywords=["alpha", "beta", "gamma"])
    engine = MutationEngine(profile)
    candidates = engine.mutate_all(profile.base_words(), max_words=25)
    assert len(candidates) <= 25


def test_mutation_applies_policy() -> None:
    profile = SeedProfile(name="acme", policy={"min_length": 10, "require_number": True})
    engine = MutationEngine(profile)
    candidates = engine.mutate_all(profile.base_words(), max_words=500)
    for word, _ in candidates:
        assert len(word) >= 10
        assert any(c.isdigit() for c in word)


# --- policy -------------------------------------------------------------------


def test_policy_filter() -> None:
    policy = {"min_length": 8, "require_upper": True, "require_special": True}
    assert passes_policy("Password!", policy)
    assert not passes_policy("short", policy)
    assert not passes_policy("alllowercase!", policy)  # no uppercase
    assert not passes_policy("NoSpecials1", policy)  # no special


# --- hashcat rules ------------------------------------------------------------


def test_rule_chain_helpers() -> None:
    assert _append_chain("24") == "$2$4"
    assert _append_chain("!@") == "$\\!$\\@"
    assert _prepend_chain("Hi") == "^i^H"  # front-push builds in reverse
    assert _sub_rule("a", "@") == "sa\\@"
    assert _sub_rule("ab", "@") is None  # multi-char src invalid


def test_rule_export_tiers_and_seeds() -> None:
    profile = SeedProfile(name="Acme", domain="acme.com", employees=["Rahul Sharma"])
    exporter = RuleExporter(profile)
    basic = exporter.build_rules("basic")
    standard = exporter.build_rules("standard")
    assert ":" in basic and "l" in basic and "u" in basic  # case rules present
    assert len(standard) >= len(basic)  # standard adds leet + years
    assert any(r.startswith("s") for r in standard)  # substitution (leet) rules
    seeds = exporter.build_seeds()
    # org name, employee name parts present (case-insensitive dedupe keeps one
    # "Acme" for the org name / domain base)
    assert "Acme" in seeds and "Rahul" in seeds and "Sharma" in seeds


# --- end-to-end via engine ----------------------------------------------------


def test_resdev_end_to_end_writes_artifacts(tmp_path: Path) -> None:
    scope = make_scope()  # allows resource-development + wordlist-generation; lab.local in scope
    engine = Engine(scope, sink=ListSink(), loader=_loader(), clock=clock_at(IN_WINDOW))
    result = engine.run_head(
        "resdev",
        options={
            "company": "Acme Corp",
            "domain": "lab.local",
            "employees": ["Rahul Sharma"],
            "max_words": 300,
            "export_rules": True,
            "rules_tier": "standard",
            "output_dir": str(tmp_path),
        },
    )
    assert result.status == "ok"
    kinds = {e.details.get("artifact") for e in result.events}
    assert "wordlist" in kinds and "hashcat-rules" in kinds
    assert all(e.attack_id == "T1587" for e in result.events)
    # artifacts actually written
    fulls = list(tmp_path.glob("*_full.txt"))
    rules = list(tmp_path.glob("*.rule"))
    assert fulls and rules
    assert fulls[0].read_text(encoding="utf-8").strip()  # non-empty wordlist


def test_resdev_out_of_scope_domain_is_blocked(tmp_path: Path) -> None:
    scope = make_scope(scope={"targets": ["10.10.0.0/24"]})  # no domain in scope
    sink = ListSink()
    engine = Engine(scope, sink=sink, loader=_loader(), clock=clock_at(IN_WINDOW))
    result = engine.run_head(
        "resdev",
        options={"domain": "evil.example.com", "output_dir": str(tmp_path)},
    )
    assert result.status == "scope-violation"
    assert any(e.outcome.value == "blocked" for e in result.events)
    assert not list(tmp_path.glob("*.txt"))  # nothing generated
