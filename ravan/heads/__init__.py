"""RAVAN heads — one subpackage per MITRE ATT&CK tactic module.

Each head is a self-contained plugin implementing
:class:`ravan.core.base.BaseHead`. The plugin loader imports these subpackages
and registers concrete heads by ``head_name``; the core engine never imports a
head directly.
"""

from __future__ import annotations
