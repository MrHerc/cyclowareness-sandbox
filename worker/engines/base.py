"""The engine interface every detonation backend implements.

An engine is anything that can take a quarantined sample and return behaviour in
the sandbox's Signal vocabulary: the team's own native Linux jail, a Qiling
emulation, or a client for an external open-source sandbox (Cuckoo / CAPEv2 /
Joe). The agent loop knows only this interface — it never learns which engine
produced a report, exactly as the backend never learns which analyzer produced a
static result.

Two invariants live here:

1. ``available()`` answers "can this engine run at all on this host right now"
   (binary present, package importable, service configured). An engine that is
   not available is skipped, never forced.
2. A ``Report`` maps one-to-one onto ``DynamicReportIn`` on the backend. The
   worker and the web service share no code, so this dataclass is the single
   place that shape is pinned down; ``to_payload()`` is the wire format.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Valid severities, mirrored from backend/app/engine/contracts.py. Kept as a
# plain tuple so this module has no dependency on the backend package.
SEVERITIES = ("info", "low", "medium", "high", "critical")


def signal(
    id: str,
    title: str,
    severity: str,
    detail: str = "",
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one Signal dict, clamping an unknown severity to ``info``."""
    if severity not in SEVERITIES:
        severity = "info"
    return {
        "id": id,
        "title": title,
        "severity": severity,
        "detail": detail,
        "evidence": evidence or {},
    }


def empty_iocs() -> dict[str, list[str]]:
    return {
        "urls": [],
        "domains": [],
        "ips": [],
        "emails": [],
        "hashes": [],
        "file_paths": [],
        "registry_keys": [],
        "mutexes": [],
    }


@dataclass
class Report:
    """One engine's findings for one sample — the ``DynamicReportIn`` body.

    ``ran=False`` with an ``unavailable_reason`` is a first-class outcome: it is
    how the worker says "I could not detonate this" without pretending the
    sample was clean. The backend records that distinction and shows it.

    ``refused=True`` narrows that to the case where the sandbox *looked at this
    sample* and declined it, as opposed to being absent, busy or broken. The
    difference decides whether trying again is worth anything: a timeout may
    succeed on the next pass, a refusal will be refused identically forever.
    """

    engine: str
    worker: str
    ran: bool = True
    unavailable_reason: str | None = None
    #: The sandbox declined this sample, and will decline it again.
    refused: bool = False
    signals: list[dict[str, Any]] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    iocs: dict[str, list[str]] = field(default_factory=empty_iocs)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    duration_ms: int = 0

    @classmethod
    def unavailable(cls, engine: str, worker: str, reason: str) -> "Report":
        return cls(engine=engine, worker=worker, ran=False, unavailable_reason=reason)

    @classmethod
    def refused_sample(cls, engine: str, worker: str, reason: str) -> "Report":
        """The sandbox rejected this sample outright — do not offer it again.

        Eight corpus samples were refused by CAPE and re-offered on every poll
        forever, because nothing distinguished "declined" from "not right now".
        Each looked like a completed, low-risk analysis; they were live Mirai and
        Gafgyt binaries that had never executed.
        """
        return cls(
            engine=engine, worker=worker, ran=False, unavailable_reason=reason, refused=True
        )

    def add_signal(self, *args: Any, **kwargs: Any) -> None:
        self.signals.append(signal(*args, **kwargs))

    def add_event(
        self, t_ms: int, kind: str, detail: str, *, unit: str = "sequence",
        origin: str = "unknown",
    ) -> None:
        """One point on the behaviour timeline.

        `unit` SAYS WHAT THE NUMBER IS, because for most callers it is not a
        time. Every engine here passes an ordinal -- `idx`, `i`, `len(calls)` --
        and the field has always been called `t_ms`, so the API, the TypeScript
        type and the tooltip ("`${e.t_ms} ms`") all reported a list index as a
        millisecond measurement. A reader comparing two events concluded one
        happened 3ms after another when the only fact available was that it came
        next.

        The field keeps its name so stored rows and the API contract do not
        break; `unit` is what a renderer must read. `sequence` means "the Nth
        thing observed" and is the honest default, since a sandbox that does not
        timestamp cannot be made to. `ms` is only correct when the source really
        carried a clock -- CAPE's `first_seen` does.
        """
        self.timeline.append(
            {"t_ms": int(t_ms), "kind": kind, "detail": detail, "unit": unit,
             "origin": origin}
        )

    def add_ioc(self, field_name: str, value: str) -> None:
        bucket = self.iocs.setdefault(field_name, [])
        if value and value not in bucket:
            bucket.append(value)

    def to_payload(self) -> dict[str, Any]:
        """The exact JSON POSTed to /api/dynamic/report/{id}."""
        # Never leak a null through fields the API models as non-null lists/dicts.
        iocs = empty_iocs()
        iocs.update({k: list(v or []) for k, v in (self.iocs or {}).items()})
        return {
            "engine": self.engine,
            "worker": self.worker,
            "ran": bool(self.ran),
            "unavailable_reason": self.unavailable_reason,
            "refused": bool(self.refused),
            "signals": list(self.signals or []),
            "facts": dict(self.facts or {}),
            "iocs": iocs,
            "duration_ms": int(self.duration_ms),
            "timeline": list(self.timeline or []),
        }


class Engine:
    """Base class. Subclasses override ``name`` and the three methods below."""

    #: Short, stable identifier that lands in ``DynamicReportIn.engine`` and, on
    #: the backend, becomes the analyzer name ``dynamic.<name>``.
    name: str = "base"

    def available(self) -> bool:
        """Can this engine run on this host right now? Cheap, no side effects."""
        raise NotImplementedError

    def supports(self, family: str) -> bool:
        """Does this engine handle this coarse content family (pe/elf/…)?"""
        raise NotImplementedError

    def run(self, sample_path: str, sha256: str, family: str) -> Report:
        """Detonate/emulate the sample and return a Report. Must not raise for
        an ordinary bad sample — return ``ran=False`` with a reason instead."""
        raise NotImplementedError

    # Convenience so every subclass can mint a Report already stamped with its
    # own name and the configured worker identity.
    def _report(self, worker: str) -> Report:
        return Report(engine=self.name, worker=worker)
