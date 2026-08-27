"""RAVAN — a ten-headed adversary emulation framework for authorized testing.

RAVAN runs configurable MITRE ATT&CK technique emulations across ten tactic
"heads", logs every action in a common structured schema, and (from Phase 5)
feeds that log into a detection-validation layer. It refuses to act outside a
declared engagement scope.
"""

from __future__ import annotations

__version__ = "0.0.0"

__all__ = ["__version__"]
