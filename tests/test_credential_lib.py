"""Tests for the shared ravan.credential library."""

from __future__ import annotations

from ravan.credential import (
    AttemptStatus,
    BruteConfig,
    BruteEngine,
    CredentialSpec,
    LockoutDetector,
    ProtocolAttacker,
    available_protocols,
    get_attacker,
    known_protocols,
    protocol_for_service,
)
from ravan.credential.attempt import AttemptResult
from ravan.credential.protocols.http_basic import HTTPBasicAttacker
from ravan.credential.protocols.redis_proto import RedisAttacker

from conftest import basic_auth_server, redis_like_server


class FakeAttacker(ProtocolAttacker):
    """Deterministic attacker: succeeds only for the configured valid pairs."""

    protocol = "fake"
    default_port = 0

    def __init__(self, valid: set[tuple[str, str]]) -> None:
        self.valid = valid
        self.calls: list[tuple[str, str]] = []

    def authenticate(
        self, host: str, port: int, username: str, password: str, timeout: float
    ) -> AttemptResult:
        self.calls.append((username, password))
        if (username, password) in self.valid:
            return self._result(host, port, username, password, AttemptStatus.SUCCESS)
        return self._result(host, port, username, password, AttemptStatus.FAILED, error="bad creds")


# --- attempt model ------------------------------------------------------------


def test_attempt_result_validity() -> None:
    ok = AttemptResult("h", 1, "ftp", "u", "p", AttemptStatus.SUCCESS)
    noauth = AttemptResult("h", 1, "redis", "", "", AttemptStatus.NOAUTH)
    bad = AttemptResult("h", 1, "ftp", "u", "p", AttemptStatus.FAILED)
    assert ok.valid and noauth.valid and not bad.valid
    assert "password" in ok.redacted()
    assert "password" not in bad.redacted()  # only surfaced for valid creds


# --- lockout detector ---------------------------------------------------------


def test_lockout_detector_window() -> None:
    now = [1000.0]
    detector = LockoutDetector(threshold=3, window=100.0, clock=lambda: now[0])
    for _ in range(3):
        detector.record_failure("h", "u")
    assert detector.is_locked_out("h", "u")
    now[0] += 200.0  # slide past the window
    assert not detector.is_locked_out("h", "u")


def test_lockout_detector_success_clears() -> None:
    detector = LockoutDetector(threshold=2)
    detector.record_failure("h", "u")
    detector.record_failure("h", "u")
    assert detector.is_locked_out("h", "u")
    detector.record_success("h", "u")
    assert not detector.is_locked_out("h", "u")


# --- credential providers -----------------------------------------------------


def test_dictionary_is_user_major() -> None:
    spec = CredentialSpec.from_options(
        {"mode": "dictionary", "users": ["a", "b"], "passwords": ["1", "2"]}, "ftp"
    )
    assert list(spec.pairs()) == [("a", "1"), ("a", "2"), ("b", "1"), ("b", "2")]


def test_spray_is_password_major() -> None:
    spec = CredentialSpec.from_options(
        {"mode": "spray", "users": ["a", "b"], "passwords": ["1", "2"]}, "ftp"
    )
    # one password across all users before moving on — the lockout-safe order
    assert list(spec.pairs()) == [("a", "1"), ("b", "1"), ("a", "2"), ("b", "2")]


def test_defaults_mode_loads_service_pairs() -> None:
    spec = CredentialSpec.from_options({"mode": "defaults", "service": "ftp"}, "ftp")
    pairs = list(spec.pairs())
    assert pairs
    assert ("ftp", "ftp") in pairs


def test_smart_mode_renders_and_skips_unfilled() -> None:
    spec = CredentialSpec.from_options(
        {"mode": "smart", "users": ["jsmith"], "company": "Acme"}, "ssh"
    )
    passwords = {p for _, p in spec.pairs()}
    assert "jsmith123" in passwords
    assert any("Acme" in p for p in passwords)  # {Company} filled
    assert all("{" not in p for p in passwords)  # no unresolved placeholders


def test_max_pairs_caps_stream() -> None:
    spec = CredentialSpec.from_options(
        {
            "mode": "dictionary",
            "users": ["a"],
            "passwords": [str(i) for i in range(100)],
            "max_pairs": 10,
        },
        "ftp",
    )
    assert len(list(spec.pairs())) == 10


# --- registry -----------------------------------------------------------------


def test_registry() -> None:
    assert "ftp" in known_protocols()
    assert "ftp" in available_protocols()  # stdlib, always available
    assert isinstance(get_attacker("ftp"), ProtocolAttacker)
    assert protocol_for_service("https") == "http-basic"
    assert protocol_for_service("ssh") == "ssh"


# --- engine (deterministic, workers=1) ----------------------------------------


def test_engine_stops_on_success() -> None:
    attacker = FakeAttacker({("admin", "p2")})
    engine = BruteEngine(attacker, BruteConfig(workers=1))
    pairs = [("admin", "p1"), ("admin", "p2"), ("admin", "p3")]
    outcome = engine.run("h", 1, iter(pairs))
    assert len(outcome.found) == 1
    assert outcome.found[0].password == "p2"
    assert ("admin", "p3") not in attacker.calls  # stopped after success
    assert outcome.skipped == 1


def test_engine_respects_lockout() -> None:
    attacker = FakeAttacker(set())  # nothing valid
    engine = BruteEngine(attacker, BruteConfig(workers=1, lockout_threshold=2))
    pairs = [("admin", f"p{i}") for i in range(5)]
    outcome = engine.run("h", 1, iter(pairs))
    # 2 failures trip the lockout guard; remaining attempts are skipped.
    assert len(attacker.calls) == 2
    assert outcome.skipped == 3
    assert not outcome.found


def test_engine_reports_unsupported() -> None:
    class Missing(FakeAttacker):
        @classmethod
        def available(cls) -> bool:
            return False

    outcome = BruteEngine(Missing(set())).run("h", 1, iter([("a", "b")]))
    assert outcome.unsupported
    assert outcome.attempts == 0


# --- protocol integration (real loopback servers) -----------------------------


def test_http_basic_attacker_success_and_fail() -> None:
    with basic_auth_server("admin", "secret") as (host, port):
        attacker = HTTPBasicAttacker(path="/")
        good = attacker.authenticate(host, port, "admin", "secret", 2.0)
        bad = attacker.authenticate(host, port, "admin", "wrong", 2.0)
    assert good.status is AttemptStatus.SUCCESS
    assert bad.status is AttemptStatus.FAILED


def test_redis_attacker_statuses() -> None:
    attacker = RedisAttacker()
    with redis_like_server("s3cr3t") as (host, port):
        assert attacker.authenticate(host, port, "", "s3cr3t", 2.0).status is AttemptStatus.SUCCESS
        assert attacker.authenticate(host, port, "", "nope", 2.0).status is AttemptStatus.FAILED
    with redis_like_server("") as (host, port):
        # server has no password set -> access is open
        assert attacker.authenticate(host, port, "", "anything", 2.0).status is AttemptStatus.NOAUTH
