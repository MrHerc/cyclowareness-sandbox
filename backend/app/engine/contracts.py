"""Cyclowareness Sandbox analysis contracts.

Every analyzer — static, dynamic, or the native engine — speaks exactly this
vocabulary, and nothing downstream of an analyzer knows which one produced a
result. That is what lets the engine run with three analyzers on a managed host
and eleven on a lab box without any other code changing.

Two rules the whole engine rests on:

1. **A Signal is the only thing that can move a score.** Analyzers do not score.
   They observe, and they say how confident the observation is. Scoring reads
   signals and nothing else, which is why the final number can always be
   explained back to a list of sentences a human can read.

2. **An analyzer that could not run says so.** It never returns an empty result
   that reads like "nothing found". `ran=False` with a reason is a first-class
   outcome, because "we did not look" and "we looked and it was clean" are
   different claims, and a security product that confuses them is worse than
   one that admits the gap.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]

SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass
class Signal:
    """One observation, stated so a human can disagree with it.

    `id` is a stable machine identifier (``pe.high_entropy``) — scoring weights
    and YARA-to-rule mappings key off it, so renaming one silently changes every
    score that ever depended on it.
    """

    id: str
    title: str
    severity: Severity
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IOCs:
    """Indicators lifted out of the sample.

    Deliberately additive and de-duplicated on merge: an indicator seen by two
    analyzers is one indicator with more support, not two.
    """

    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    file_paths: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    mutexes: list[str] = field(default_factory=list)

    FIELDS = (
        "urls",
        "domains",
        "ips",
        "emails",
        "hashes",
        "file_paths",
        "registry_keys",
        "mutexes",
    )

    def merge(self, other: "IOCs") -> "IOCs":
        merged = IOCs()
        for name in self.FIELDS:
            seen: dict[str, None] = {}
            for value in [*getattr(self, name), *getattr(other, name)]:
                seen.setdefault(value, None)
            setattr(merged, name, list(seen))
        return merged

    def total(self) -> int:
        return sum(len(getattr(self, name)) for name in self.FIELDS)

    def to_dict(self) -> dict[str, list[str]]:
        return {name: getattr(self, name) for name in self.FIELDS}


@dataclass
class AnalyzerResult:
    """What one analyzer produced for one sample."""

    analyzer: str
    ran: bool = True
    #: Why the analyzer produced nothing. Required whenever ``ran`` is False —
    #: "not installed on this host", "wrong file type", "timed out at 30s".
    unavailable_reason: str | None = None
    signals: list[Signal] = field(default_factory=list)
    #: Structured observations for the report: PE sections, macro names, the
    #: archive tree. Never scored directly; scoring only reads signals.
    facts: dict[str, Any] = field(default_factory=dict)
    iocs: IOCs = field(default_factory=IOCs)
    duration_ms: int = 0

    @classmethod
    def unavailable(cls, analyzer: str, reason: str) -> "AnalyzerResult":
        return cls(analyzer=analyzer, ran=False, unavailable_reason=reason)

    @classmethod
    def not_applicable(cls, analyzer: str, file_type: str) -> "AnalyzerResult":
        return cls(
            analyzer=analyzer,
            ran=False,
            unavailable_reason=f"does not handle {file_type} samples",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "analyzer": self.analyzer,
            "ran": self.ran,
            "unavailable_reason": self.unavailable_reason,
            "signals": [s.to_dict() for s in self.signals],
            "facts": self.facts,
            "iocs": self.iocs.to_dict(),
            "duration_ms": self.duration_ms,
        }


@dataclass
class Sample:
    """The thing under analysis, already quarantined.

    ``path`` is inside the quarantine tree and is never executable. Analyzers
    receive this, never a user-supplied path, and never the original filename as
    a filesystem path — the filename is attacker-controlled data and is carried
    as metadata only.
    """

    path: str
    size_bytes: int
    sha256: str
    md5: str
    mime: str
    magic: str
    #: Extension the submitter claimed, lowercased, with the dot: ".exe".
    claimed_extension: str
    original_name: str
    #: True when the content does not match the claimed extension — on its own a
    #: strong signal, and the reason identification is a separate step.
    extension_mismatch: bool = False
    #: Coarse content family from identify.py (pe/elf/office/script/pdf/archive/
    #: diskimage/unknown). The registry dispatches analyzers on it.
    family: str = "unknown"

    def read(self, limit: int | None = None) -> bytes:
        with open(self.path, "rb") as fh:
            return fh.read() if limit is None else fh.read(limit)


# --- risk banding -------------------------------------------------------------
# Fixed by the sandbox banding specification: 0-29 Low, 30-59 Medium, 60-79 High,
# 80-100 Critical.

RISK_BANDS: tuple[tuple[int, str], ...] = (
    (80, "critical"),
    (60, "high"),
    (30, "medium"),
    (0, "low"),
)


def risk_level(score: float) -> str:
    for threshold, label in RISK_BANDS:
        if score >= threshold:
            return label
    return "low"
