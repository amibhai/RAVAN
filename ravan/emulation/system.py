"""Platform detection for the emulation heads.

The execution/persistence atomics differ by OS; this centralises the check so
each atomic can declare which platforms it applies to.
"""

from __future__ import annotations

import os
import platform
import shutil
from enum import StrEnum


class Platform(StrEnum):
    WINDOWS = "windows"
    LINUX = "linux"
    DARWIN = "darwin"

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


def current_platform() -> Platform:
    system = platform.system().lower()
    if system.startswith("win"):
        return Platform.WINDOWS
    if system == "darwin":
        return Platform.DARWIN
    return Platform.LINUX


def is_windows() -> bool:
    return current_platform() is Platform.WINDOWS


def which(executable: str) -> str | None:
    """Return the resolved path of an executable if it is on PATH, else None.

    Used by atomics to skip an interpreter/tool that isn't installed rather
    than fail the whole head.
    """
    return shutil.which(executable)


def is_admin() -> bool:
    """Best-effort elevation check. Atomics use user-level mechanisms so they
    rarely need this, but admin-only atomics degrade to SKIPPED when False.

    Uses getattr so the platform-specific APIs (ctypes.windll / os.geteuid)
    resolve at runtime without tripping cross-platform type checking.
    """
    try:
        if is_windows():
            import ctypes

            windll = getattr(ctypes, "windll", None)
            if windll is None:
                return False
            return bool(windll.shell32.IsUserAnAdmin())
        geteuid = getattr(os, "geteuid", None)
        return geteuid is not None and geteuid() == 0
    except OSError:
        return False


ALL_PLATFORMS: frozenset[Platform] = frozenset(Platform)
UNIX_PLATFORMS: frozenset[Platform] = frozenset({Platform.LINUX, Platform.DARWIN})


__all__ = [
    "ALL_PLATFORMS",
    "UNIX_PLATFORMS",
    "Platform",
    "current_platform",
    "is_admin",
    "is_windows",
    "which",
]
