"""Per-family static analyzers, and the registry that dispatches to them.

Each module exposes:
  ``NAME``     the analyzer's id, used as the key in the job's analysis payload
  ``FAMILY`` / ``FAMILIES`` / ``HANDLES``   the identify.py families it claims,
             or ``"*"`` for an analyzer that runs on everything
  ``analyze(sample) -> AnalyzerResult``

Nothing here ever executes a sample.

The registry is deliberately forgiving about which of the three family
attributes a module declares, and deliberately unforgiving about failure: an
analyzer that raises is converted into an honest ``unavailable`` result rather
than being allowed to fail the whole job. One broken parser must not cost the
analyst every other finding on the sample.
"""
from __future__ import annotations

import importlib
import logging
import time
from typing import Any, Callable, Iterable

from ..contracts import AnalyzerResult, Sample

logger = logging.getLogger("sandbox.analyzers")

#: Import order is the order results appear in the report.
_MODULE_NAMES = ("generic", "pe", "office", "scripts", "pdf", "elf", "apk", "jar", "diskimage", "intel")

_import_failures: dict[str, str] = {}


def _families(module: Any) -> tuple[str, ...]:
    for attr in ("FAMILIES", "HANDLES", "FAMILY"):
        value = getattr(module, attr, None)
        if value is None:
            continue
        if isinstance(value, str):
            return (value,)
        return tuple(value)
    # No declaration: assume the module name is the family it handles.
    return (getattr(module, "NAME", "") or "",)


class Registered:
    __slots__ = ("name", "families", "fn")

    def __init__(self, name: str, families: tuple[str, ...], fn: Callable[[Sample], AnalyzerResult]):
        self.name = name
        self.families = families
        self.fn = fn

    def handles(self, family: str) -> bool:
        return "*" in self.families or family in self.families


_registry: list[Registered] | None = None


def registry() -> list[Registered]:
    global _registry
    if _registry is not None:
        return _registry

    found: list[Registered] = []
    for mod_name in _MODULE_NAMES:
        try:
            module = importlib.import_module(f"{__name__}.{mod_name}")
        except Exception as exc:  # noqa: BLE001
            # A module that will not import is a deployment problem, not a
            # reason to lose the analyzers that do work. It surfaces through
            # `unavailable_analyzers()` so the UI can state the gap.
            logger.warning("analyzer %s failed to import: %s", mod_name, exc)
            _import_failures[mod_name] = f"{type(exc).__name__}: {exc}"
            continue
        fn = getattr(module, "analyze", None)
        if not callable(fn):
            _import_failures[mod_name] = "module exposes no analyze() function"
            continue
        found.append(Registered(getattr(module, "NAME", mod_name), _families(module), fn))

    _registry = found
    return _registry


def unavailable_analyzers() -> dict[str, str]:
    registry()
    return dict(_import_failures)


def run_all(sample: Sample, family: str) -> list[AnalyzerResult]:
    """Every analyzer that claims this family, plus the universal ones."""
    results: list[AnalyzerResult] = []
    for entry in registry():
        if not entry.handles(family):
            continue
        started = time.perf_counter()
        try:
            result = entry.fn(sample)
        except Exception as exc:  # noqa: BLE001 — a hostile sample crashed a parser
            logger.exception("analyzer %s raised on %s", entry.name, sample.sha256[:12])
            result = AnalyzerResult.unavailable(
                entry.name, f"analyzer raised {type(exc).__name__} on this sample"
            )
        if not isinstance(result, AnalyzerResult):
            result = AnalyzerResult.unavailable(
                entry.name, "analyzer returned something other than an AnalyzerResult"
            )
        if not result.duration_ms:
            result.duration_ms = int((time.perf_counter() - started) * 1000)
        results.append(result)
    return results


def names_for(family: str) -> list[str]:
    return [e.name for e in registry() if e.handles(family)]


def all_names() -> Iterable[str]:
    return (e.name for e in registry())
