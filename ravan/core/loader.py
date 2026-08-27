"""Plugin discovery for RAVAN heads.

Heads live under ``ravan.heads.*``. The loader imports those packages, collects
concrete :class:`BaseHead` subclasses, and maps them by ``head_name``. A broken
head package is isolated: it is recorded as a load error rather than crashing
discovery of the others.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import Protocol

import ravan.heads
from ravan.core.base import BaseHead
from ravan.core.exceptions import DuplicateHeadError, HeadLoadError

#: Only classes defined under this package prefix are treated as real heads,
#: so test/embedded subclasses defined elsewhere never leak into discovery.
_HEADS_PACKAGE = "ravan.heads"


class Loader(Protocol):
    """The interface the engine depends on to obtain heads."""

    load_errors: list[HeadLoadError]

    def discover(self) -> dict[str, type[BaseHead]]: ...


def _all_head_subclasses() -> list[type[BaseHead]]:
    """Every subclass of :class:`BaseHead`, recursively."""
    found: list[type[BaseHead]] = []
    stack: list[type[BaseHead]] = list(BaseHead.__subclasses__())
    while stack:
        sub = stack.pop()
        found.append(sub)
        stack.extend(sub.__subclasses__())
    return found


class HeadLoader:
    """Discovers heads by importing every subpackage of ``ravan.heads``."""

    def __init__(self) -> None:
        self.load_errors: list[HeadLoadError] = []

    def _import_head_packages(self) -> None:
        self.load_errors = []
        for module_info in pkgutil.walk_packages(
            ravan.heads.__path__, prefix=f"{_HEADS_PACKAGE}."
        ):
            try:
                importlib.import_module(module_info.name)
            except Exception as exc:
                self.load_errors.append(
                    HeadLoadError(f"failed to import head module {module_info.name!r}: {exc!r}")
                )

    def discover(self) -> dict[str, type[BaseHead]]:
        self._import_head_packages()
        heads: dict[str, type[BaseHead]] = {}
        for cls in _all_head_subclasses():
            if not cls.__module__.startswith(_HEADS_PACKAGE):
                continue
            if inspect.isabstract(cls):
                continue
            name = getattr(cls, "head_name", None)
            if not name:
                self.load_errors.append(
                    HeadLoadError(
                        f"head class {cls.__module__}.{cls.__qualname__} defines no head_name"
                    )
                )
                continue
            missing = [
                attr
                for attr in ("technique_id", "technique_name", "tactic")
                if getattr(cls, attr, None) is None
            ]
            if missing:
                self.load_errors.append(
                    HeadLoadError(
                        f"head {name!r} ({cls.__qualname__}) is missing metadata: "
                        f"{', '.join(missing)}"
                    )
                )
                continue
            if name in heads and heads[name] is not cls:
                raise DuplicateHeadError(
                    f"two heads claim the name {name!r}: "
                    f"{heads[name].__qualname__} and {cls.__qualname__}"
                )
            heads[name] = cls
        return heads


class StaticLoader:
    """A loader over an explicit mapping. Used for embedding and tests."""

    def __init__(self, heads: dict[str, type[BaseHead]]) -> None:
        self._heads = dict(heads)
        self.load_errors: list[HeadLoadError] = []

    def discover(self) -> dict[str, type[BaseHead]]:
        return dict(self._heads)


__all__ = ["HeadLoader", "Loader", "StaticLoader"]
