"""Shared credential-testing library used by the credential-access and
lateral-movement heads: protocol attackers, lockout-safe brute engine, and
attack-mode credential providers."""

from __future__ import annotations

from ravan.credential.attempt import AttemptResult, AttemptStatus
from ravan.credential.base import ProtocolAttacker
from ravan.credential.credentials import CredentialSpec
from ravan.credential.engine import BruteConfig, BruteEngine, BruteOutcome
from ravan.credential.lockout import LockoutDetector
from ravan.credential.protocols import (
    available_protocols,
    get_attacker,
    known_protocols,
    protocol_for_service,
)

__all__ = [
    "AttemptResult",
    "AttemptStatus",
    "BruteConfig",
    "BruteEngine",
    "BruteOutcome",
    "CredentialSpec",
    "LockoutDetector",
    "ProtocolAttacker",
    "available_protocols",
    "get_attacker",
    "known_protocols",
    "protocol_for_service",
]
