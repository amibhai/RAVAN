"""Lateral Movement head package (Head #7).

Validates credential reuse across in-scope hosts over the shared
``ravan.credential`` library (ATT&CK T1021 Remote Services / T1078 Valid
Accounts).
"""

from __future__ import annotations

from ravan.heads.lateral_movement.head import LateralMovementHead

__all__ = ["LateralMovementHead"]
