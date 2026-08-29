"""Credential Access head package (Head #6).

Lockout-aware credential brute-forcing over the shared ``ravan.credential``
library (ATT&CK T1110, Brute Force).
"""

from __future__ import annotations

from ravan.heads.credential_access.head import CredentialAccessHead

__all__ = ["CredentialAccessHead"]
