"""Request/response shapes for the API.

Deliberately thin: the heavy analysis payload is already well-structured JSON on
the job row, so these models choose which parts of it a caller sees rather than
re-describing all of it. The list view never carries the full analysis — a queue
of fifty jobs should be fifty summaries, not fifty forensic reports.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class JobSummary(BaseModel):
    public_id: str
    source: str
    original_name: str
    submitted_url: str | None
    sha256: str
    size_bytes: int
    mime: str
    family: str
    status: str
    stage: str
    risk_level: str
    final_score: float
    #: The engine's answer, carried on the summary because it is the first thing
    #: anyone looks at. Omitting it made the dashboard's headline metrics read
    #: "MALICIOUS 0" and "Not classified 5" for five jobs that were every one of
    #: them malicious - the frontend was already handling a missing verdict
    #: gracefully, so nothing errored and the numbers were simply wrong. It costs
    #: nothing: the column is JSON on the row already loaded for this response.
    verdict: dict | None = None
    created_at: datetime
    completed_at: datetime | None

    @classmethod
    def of(cls, job) -> "JobSummary":
        return cls(
            public_id=job.public_id,
            source=job.source,
            original_name=job.original_name,
            submitted_url=job.submitted_url,
            sha256=job.sha256,
            size_bytes=job.size_bytes,
            mime=job.mime,
            family=job.family,
            status=job.status,
            stage=job.stage,
            risk_level=job.risk_level,
            final_score=job.final_score,
            verdict=job.verdict,
            created_at=job.created_at,
            completed_at=job.completed_at,
        )


#: The largest `offset` any paged endpoint accepts.
#:
#: Every offset in this codebase was declared `ge=0` with no ceiling, so the
#: value went to the database unbounded. Postgres OFFSET is a bigint, and
#: `?offset=9223372036854775808` — one past int64 — reached it and came back as
#: a **500 in text/plain** from `GET /api/jobs`, `GET /api/audit` and
#: `GET /api/audit/export`, on a single authenticated GET with no body.
#:
#: A billion is not a guess at a real table size; it is a number far past any
#: deployment this product can physically hold (the quarantine alone would be
#: petabytes) that still leaves the arithmetic nowhere near the type's edge.
#: Callers never need to guess anyway: every paged response carries its total.
MAX_OFFSET = 1_000_000_000


class JobPage(BaseModel):
    """One page of the queue, and how much of it there is.

    `GET /api/jobs` used to return a bare array capped at 50 with no `offset`
    and no total. Both pages that read it sent no parameters and presented the
    result as everything: the Queue's own lede says "Every sample submitted to
    this deployment", and the dashboard counted its tiles from whatever the page
    happened to contain. Measured on the live deployment, the "Malicious" tile
    read **10** against a true 151, and 71 jobs could not be reached through the
    endpoint at any limit, because the ignored `offset` meant there was no
    second page to ask for.

    `total` is the count BEFORE limit and offset and after every filter, which
    is what makes "showing 50 of 269" a sentence the UI can write truthfully.
    """

    items: list[JobSummary]
    total: int
    limit: int
    offset: int
    #: Pass back as `?cursor=` for the next page. `None` means this is the last.
    #:
    #: OFFSET counts rows from the top and is only correct while the top does
    #: not move; this table's whole purpose is that it moves. A cursor names the
    #: last row seen, so a submission arriving above it cannot shift the page.
    next_cursor: str | None = None


class FamilyCount(BaseModel):
    family: str
    count: int


class JobStats(BaseModel):
    """The dashboard's numbers, counted in SQL over the whole tenant.

    The dashboard cannot be honest by paging: it needs counts over everything,
    and the page limit is 200 against a table that already holds more. Every
    figure here is the aggregate, so the tiles stop being a property of how many
    rows the last poll happened to fetch.

    The definitions mirror `frontend/src/lib/format.ts` exactly, because two
    definitions of "needs attention" is a defect waiting to happen: a job counts
    when its verdict is malicious or suspicious, or — when it has no verdict at
    all — when it scored 30 or more.
    """

    total: int
    completed: int
    in_flight: int
    #: Keyed by verdict, over completed jobs. Always carries all four keys, so
    #: the UI never has to distinguish "none" from "not reported".
    verdicts: dict[str, int]
    needs_attention: int
    average_score: float
    families: list[FamilyCount]
    #: Worst first, by verdict and then by score — the same order the dashboard
    #: applied client-side when it could only see one page.
    top_risk: list[JobSummary]


class JobDetail(JobSummary):
    md5: str
    magic: str
    extension_mismatch: bool
    submitted_by: str | None
    error: str | None
    tiers: dict[str, Any]
    analysis: dict[str, Any]
    dynamic: dict[str, Any]
    iocs: dict[str, list[str]]
    score_breakdown: dict[str, Any]
    impact: dict[str, Any]
    verdict: dict[str, Any]
    mitre: list[dict[str, Any]]
    rule_score: float
    ai_score: float
    feedback: str | None
    archive_path: str | None
    duration_ms: int | None
    children: list[JobSummary]

    @classmethod
    def of(cls, job, children=None) -> "JobDetail":  # type: ignore[override]
        base = JobSummary.of(job).model_dump()
        # The summary now carries the verdict too, but as `dict | None` — a job
        # mid-analysis has no verdict yet. The detail view promises a dict, and
        # normalises None to {} below, so drop the summary's copy rather than
        # passing the same keyword twice.
        base.pop("verdict", None)
        return cls(
            **base,
            md5=job.md5,
            magic=job.magic,
            extension_mismatch=bool(job.extension_mismatch),
            submitted_by=job.submitted_by,
            error=job.error,
            tiers=job.tiers or {},
            analysis=job.analysis or {},
            dynamic=job.dynamic or {},
            iocs=job.iocs or {},
            score_breakdown=job.score_breakdown or {},
            # `cvss` is what the column was called before the rating was renamed;
            # a job object carrying only the old attribute still serialises.
            impact=getattr(job, "impact", None) or getattr(job, "cvss", None) or {},
            verdict=job.verdict or {},
            mitre=job.mitre or [],
            rule_score=job.rule_score,
            ai_score=job.ai_score,
            feedback=job.feedback,
            archive_path=job.archive_path,
            duration_ms=job.duration_ms,
            children=[JobSummary.of(c) for c in (children or [])],
        )


class SubmitURLRequest(BaseModel):
    url: str


class PasswordRequest(BaseModel):
    password: str


class FeedbackRequest(BaseModel):
    verdict: str  # "false_positive" | "true_positive"
    note: str | None = None


# --- auth --------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    expires_at: int
    subject: str


# --- dynamic tier ingest -----------------------------------------------------
class SignalIn(BaseModel):
    id: str
    title: str
    severity: str = "info"
    detail: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)


class IOCsIn(BaseModel):
    urls: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)
    file_paths: list[str] = Field(default_factory=list)
    registry_keys: list[str] = Field(default_factory=list)
    mutexes: list[str] = Field(default_factory=list)


class DynamicReportIn(BaseModel):
    """What an off-host worker posts back after detonating a sample."""

    engine: str  # "native" | "cuckoo" | "capev2" | "firejail" | "qiling" | ...
    worker: str = "worker"
    ran: bool = True
    unavailable_reason: str | None = None
    #: The sandbox declined this sample, rather than being unavailable. Terminal:
    #: the job is not offered for detonation again. Defaults False, so a worker
    #: that predates the field keeps the old retrying behaviour.
    refused: bool = False
    signals: list[SignalIn] = Field(default_factory=list)
    facts: dict[str, Any] = Field(default_factory=dict)
    iocs: IOCsIn = Field(default_factory=IOCsIn)
    duration_ms: int = 0
    #: A behavior timeline the UI graphs: ordered {t_ms, kind, detail} events.
    timeline: list[dict[str, Any]] = Field(default_factory=list)


# --- admin -------------------------------------------------------------------
class WeightsUpdate(BaseModel):
    """Hackathon-tunable aggregation weights (rule vs. AI split).

    Bounded here as well as in ``scoring.set_weights`` so the API answers 422
    with the usual ``{"detail": [...]}`` rather than letting a bad number reach
    the engine. ``allow_inf_nan=False`` is the load-bearing part: ``NaN`` passed
    every comparison in the engine's own validation (``nan <= 0`` and
    ``nan < 0`` are both False), normalised to ``nan/nan``, and left the process
    weights non-finite — after which ``GET /api/admin/weights``,
    ``/api/capabilities`` and the signed export all returned 500, and every new
    submission wrote a non-finite ``final_score``.

    The ceiling is not arbitrary. Only the RATIO matters, so 1e6 expresses every
    split anyone could want, and two values at that bound still sum to a finite
    number. Without it, ``1e308 + 1e308`` overflows to ``inf``, each weight
    normalises to ``inf`` divided into itself — ``0.0`` — and the endpoint
    returned **200** for exactly the ``{0, 0}`` state it rejects with 422 when
    asked for it directly. Every verdict after that scored 0.0/low while its own
    body still carried rule_score 54.0 and three high-severity reasons.
    """

    model_config = {"allow_inf_nan": False}

    rule_weight: float | None = Field(default=None, ge=0.0, le=1e6)
    ai_weight: float | None = Field(default=None, ge=0.0, le=1e6)
