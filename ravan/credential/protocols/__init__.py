"""Registry of protocol attackers.

The pure-stdlib protocols are always available; SSH is available only when
paramiko is installed. Config-driven protocols are built via ``from_config``.
"""

from __future__ import annotations

from ravan.credential.base import ProtocolAttacker
from ravan.credential.protocols.ftp import FTPAttacker
from ravan.credential.protocols.http_basic import HTTPBasicAttacker
from ravan.credential.protocols.http_form import HTTPFormAttacker
from ravan.credential.protocols.imap import IMAPAttacker
from ravan.credential.protocols.pop3 import POP3Attacker
from ravan.credential.protocols.redis_proto import RedisAttacker
from ravan.credential.protocols.smtp import SMTPAttacker
from ravan.credential.protocols.ssh import SSHAttacker
from ravan.credential.protocols.telnet import TelnetAttacker

PROTOCOLS: dict[str, type[ProtocolAttacker]] = {
    "ftp": FTPAttacker,
    "ssh": SSHAttacker,
    "http-basic": HTTPBasicAttacker,
    "http-form": HTTPFormAttacker,
    "smtp": SMTPAttacker,
    "pop3": POP3Attacker,
    "imap": IMAPAttacker,
    "telnet": TelnetAttacker,
    "redis": RedisAttacker,
}

# Map a recon-detected service (or open port) onto a credential protocol.
SERVICE_PROTOCOL: dict[str, str] = {
    "ftp": "ftp",
    "ssh": "ssh",
    "http": "http-basic",
    "https": "http-basic",
    "http-proxy": "http-basic",
    "smtp": "smtp",
    "smtps": "smtp",
    "submission": "smtp",
    "pop3": "pop3",
    "pop3s": "pop3",
    "imap": "imap",
    "imaps": "imap",
    "telnet": "telnet",
    "redis": "redis",
}


def known_protocols() -> list[str]:
    return list(PROTOCOLS)


def available_protocols() -> list[str]:
    """Protocols whose backend can actually run in this environment."""
    return [name for name, cls in PROTOCOLS.items() if cls.available()]


def default_port(protocol: str) -> int:
    return PROTOCOLS[protocol].default_port


def get_attacker(protocol: str, config: dict[str, object] | None = None) -> ProtocolAttacker:
    """Instantiate the attacker for ``protocol``. Raises ``KeyError`` if the
    protocol is unknown."""
    cls = PROTOCOLS[protocol]
    return cls.from_config(config or {})


def protocol_for_service(service: str, port: int = 0) -> str | None:
    """Best-effort mapping of a recon service/port to a credential protocol."""
    svc = service.lower().strip()
    if svc in SERVICE_PROTOCOL:
        return SERVICE_PROTOCOL[svc]
    for name, cls in PROTOCOLS.items():
        if cls.default_port == port:
            return name
    return None


__all__ = [
    "PROTOCOLS",
    "SERVICE_PROTOCOL",
    "available_protocols",
    "default_port",
    "get_attacker",
    "known_protocols",
    "protocol_for_service",
]
