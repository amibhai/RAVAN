"""Tests for plugin (head) discovery."""

from __future__ import annotations

from ravan.core.loader import HeadLoader
from ravan.heads.recon.head import ReconHead
from ravan.schemas.events import Tactic


def test_discovers_recon_head() -> None:
    heads = HeadLoader().discover()
    assert "recon" in heads
    assert heads["recon"] is ReconHead


def test_exposes_active_heads() -> None:
    # Phases 1-3 activate seven heads; the remaining tactic subpackages are still
    # empty stubs and register nothing.
    heads = HeadLoader().discover()
    assert set(heads) == {
        "recon", "resdev", "credaccess", "lateral", "execution", "persistence", "initaccess"
    }


def test_discovery_has_no_load_errors() -> None:
    loader = HeadLoader()
    loader.discover()
    assert loader.load_errors == []


def test_recon_metadata_is_complete() -> None:
    assert ReconHead.head_name == "recon"
    assert ReconHead.technique_id == "T1595"
    assert ReconHead.tactic is Tactic.RECONNAISSANCE
    assert "active-scan" in ReconHead.required_permissions
