"""Resource Development head package (Head #2).

Ports wordsmith's OSINT-seeded wordlist + hashcat-rule generation engine into
the RAVAN plugin interface (ATT&CK T1587, Develop Capabilities).
"""

from __future__ import annotations

from ravan.heads.resource_development.head import ResourceDevelopmentHead

__all__ = ["ResourceDevelopmentHead"]
