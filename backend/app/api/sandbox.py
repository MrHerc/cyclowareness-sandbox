"""The analysis API — submit a sample, watch it analysed, read the verdict, export it.

Route shape follows the brief's REST hint (``/analyze`` to submit, ``/result``
to read) while keeping a job-centric set of routes for the UI. Analysis runs on
the background runner, not inside the request: a request that blocks for a full
analysis is one an attacker can hold open to exhaust the server. Submission
returns a job id immediately; the client polls.

Every mutating route requires an authenticated analyst. File analysis accepts
hostile input by design and must never be anonymous.
"""
from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
import re
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response
from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.orm import Session

from .. import audit, metrics, sovereignty
from ..auth import Identity, require_analyst
from ..config import Settings, get_settings
from ..db import get_db
from ..remote import client_ip
from ..engine import attestation, pipeline
from ..engine import incident as incident_mod
from ..engine import report as report_mod
from ..engine.fetcher import FetchFailed, UnsafeURL, fetch
from ..engine.models import Feedback, JobSource, JobStatus, SandboxJob
from ..engine.storage import EmptySample, SampleTooLarge, store_stream
from ..runner import submit_analysis
from ..schemas import (
    MAX_OFFSET,
    FamilyCount,
    FeedbackRequest,
    JobDetail,
    JobPage,
    JobStats,
    JobSummary,
    PasswordRequest,
    SubmitURLRequest,
)

logger = logging.getLogger("sandbox.api")

router = APIRouter(prefix="/api", tags=["analysis"])


def _max_bytes(settings: Settings) -> int:
    return max(1, settings.max_sample_mb) * 1024 * 1024


def _trace(
    request: Request,
    identity: Identity,
    action: str,
    *,
    public_id: str = "",
    detail: dict | None = None,
) -> None:
    """Append this operation to the chain of custody.

    Everything that touches a sample goes through here. The question an auditor
    asks is not "was the verdict right" but "who did what to this evidence, and
    when" — and an answer with gaps in it is not an answer. ``audit.record``
    swallows its own failures, so a chain problem can never break the request.
    """
    audit.record(
        action=action,
        actor=identity.subject,
        actor_method=identity.method,
        tenant=identity.tenant,
        object_type="sample" if public_id else "",
        object_id=public_id,
        source_ip=client_ip(request),
        detail=detail,
    )


def _attachment(original_name: str | None, fallback: str, suffix: str) -> str:
    """A `Content-Disposition` an HTTP header can actually carry.

    HTTP header values are latin-1. The old sanitiser kept any character for
    which `str.isalnum()` is true — and `str.isalnum()` is true for `ə`, for
    `ж`, for `文`: Python is right that they are letters, and latin-1 has
    nowhere to put them. So downloading the PDF for a file named
    `raport-2026-ə-ü.txt` was a **500**, from Starlette, while every other
    export of the same job returned 200. Found by uploading a file named the
    way the people who will use this product name files.

    Two names go out, per RFC 6266. `filename*` carries the real one,
    percent-encoded UTF-8, for anything from the last fifteen years;
    `filename=` carries an ASCII reduction for the rest. The ASCII form is also
    what makes header injection impossible — a name containing a quote, a
    newline or a semicolon cannot survive the filter — and the percent-encoding
    does the same job for the starred form.
    """
    name = (original_name or "").strip()
    ascii_stem = "".join(c for c in name if c.isascii() and (c.isalnum() or c in "._-"))
    # `/` is already gone, so `..` cannot traverse anything — but a name that
    # still reads like a path is one a client may yet interpret as one, and
    # nothing is lost by collapsing it.
    ascii_stem = re.sub(r"\.{2,}", ".", ascii_stem).strip("._-")[:60]
    # A job with no usable name is identified by the job, not by the word
    # "report": three downloads called `sandbox-report.pdf` in one folder are
    # three files an analyst cannot tell apart.
    stem = ascii_stem or fallback
    encoded = quote(f"sandbox-{name or fallback}{suffix}", safe="")
    return f"attachment; filename=\"sandbox-{stem}{suffix}\"; filename*=UTF-8''{encoded}"


def _job_or_404(db: Session, public_id: str, identity: Identity) -> SandboxJob:
    """The one door to a single job — and therefore the whole isolation boundary.

    Scoped in the WHERE clause, not checked after loading. A fetch-then-compare
    still reads the row, and every later refactor that forgets the comparison
    silently opens the door; a query that cannot see the row cannot leak it.

    404, never 403. "You may not see this job" and "this job exists" are the same
    sentence to anyone probing public ids, and confirming existence is itself the
    leak — a competitor could learn how much a rival is analysing without ever
    reading a report.
    """
    job = db.execute(
        select(SandboxJob)
        .where(SandboxJob.public_id == public_id)
        .where(SandboxJob.tenant_id == identity.tenant)
    ).scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    return job


# --- submission --------------------------------------------------------------
@router.post("/analyze", response_model=JobDetail, status_code=201)
async def analyze(
    request: Request,
    file: UploadFile = File(...),
    password: str | None = Form(default=None),
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
    settings: Settings = Depends(get_settings),
):
    """Submit a file. Bytes stream straight into quarantine, hashed as they go."""
    try:
        stored = store_stream(file.file, max_bytes=_max_bytes(settings))
    except SampleTooLarge as exc:
        metrics.upload_rejects_total.labels(reason="too_large").inc()
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except EmptySample as exc:
        metrics.upload_rejects_total.labels(reason="empty").inc()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        await file.close()

    job = pipeline.new_job(
        db,
        stored,
        original_name=file.filename or "upload",
        source=JobSource.UPLOAD,
        submitted_by=identity.subject,
        tenant=identity.tenant,
    )
    db.commit()
    metrics.uploads_total.labels(source="upload").inc()
    _trace(request, identity, audit.AuditAction.SAMPLE_SUBMITTED, public_id=job.public_id,
           detail={"source": "upload", "filename": job.original_name, "sha256": job.sha256,
                   "size_bytes": job.size_bytes})
    submit_analysis(job.id, password)
    db.refresh(job)
    return JobDetail.of(job)


@router.post("/analyze/url", response_model=JobDetail, status_code=201)
def analyze_url(
    request: Request,
    payload: SubmitURLRequest,
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
    settings: Settings = Depends(get_settings),
):
    """Submit a URL. The server downloads it — after refusing to fetch anything
    that resolves to a private, loopback or cloud-metadata address (SSRF guard).

    This is the one outbound connection sovereign mode permits by default, and it
    is permitted because the analyst chose the destination. A deployment that
    closes even this (``SOVEREIGN_ALLOW_URL_FETCH=false``) is refused here, at
    the only place a URL fetch can be started.
    """
    try:
        sovereignty.check(sovereignty.URL_FETCH, detail=payload.url[:200])
    except sovereignty.OutboundRefused as exc:
        metrics.fetch_failures_total.labels(reason="sovereign_mode").inc()
        raise HTTPException(status_code=403, detail=exc.reason) from exc

    try:
        with metrics.timed(metrics.fetch_duration):
            fetched = fetch(payload.url, max_bytes=_max_bytes(settings))
    except UnsafeURL as exc:
        metrics.fetch_failures_total.labels(reason="unsafe").inc()
        raise HTTPException(status_code=422, detail=f"Refusing to fetch: {exc}") from exc
    except SampleTooLarge as exc:
        metrics.fetch_failures_total.labels(reason="too_large").inc()
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except FetchFailed as exc:
        metrics.fetch_failures_total.labels(reason="failed").inc()
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    job = pipeline.new_job(
        db,
        fetched.stored,
        original_name=fetched.suggested_name,
        source=JobSource.URL,
        submitted_url=payload.url[:2000],
        submitted_by=identity.subject,
        tenant=identity.tenant,
    )
    db.commit()
    metrics.uploads_total.labels(source="url").inc()
    _trace(request, identity, audit.AuditAction.SAMPLE_SUBMITTED, public_id=job.public_id,
           detail={"source": "url", "url": (job.submitted_url or "")[:300], "sha256": job.sha256})
    submit_analysis(job.id)
    db.refresh(job)
    return JobDetail.of(job)


# --- reading -----------------------------------------------------------------
@router.get("/result/{public_id}", response_model=JobDetail)
def result(
    public_id: str,
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
):
    """The verdict and full analysis for one job (the ``/result`` endpoint)."""
    job = _job_or_404(db, public_id, identity)
    # Scoped too, though a child always inherits its parent's tenant so this
    # should be redundant. It is here because "should be" is doing all the work
    # in that sentence: a future path that creates a child some other way turns a
    # redundant filter into the only thing standing between two customers.
    children = db.execute(
        select(SandboxJob)
        .where(SandboxJob.parent_job_id == job.id)
        .where(SandboxJob.tenant_id == identity.tenant)
        .order_by(SandboxJob.final_score.desc())
    ).scalars().all()
    return JobDetail.of(job, children=children)


def _visible_jobs(identity: Identity, status: str | None = None):
    """The rows this caller may see, before any paging.

    Scoped BEFORE the limit, never after. Filtering a page of results in Python
    would silently shrink every page — and the same mistake in the worker queue
    (LIMIT in SQL, filter in Python) once returned an empty list forever with a
    hundred jobs waiting behind it.
    """
    conditions = [
        SandboxJob.tenant_id == identity.tenant,
        # Top-level jobs only; archive members are shown nested under their parent.
        SandboxJob.parent_job_id.is_(None),
    ]
    if status:
        conditions.append(SandboxJob.status == status)
    return conditions


@router.get("/jobs", response_model=JobPage)
def list_jobs(
    # Shaped, not just typed. `status` went to the driver as whatever arrived,
    # and `?status=%00` is a **500 in text/plain** on Postgres — "text fields
    # cannot contain NUL (0x00) bytes" — from any authenticated caller, on the
    # product's main list endpoint. Invisible to the suite by construction:
    # SQLite accepts NUL in a bound parameter, so only a real deployment fails.
    # A status is a lower-case word; nothing else can reach the query.
    #
    # The shape is validated here and the VALUE below, in the handler: a status
    # that is not one a job can hold returned `200 []`, which is indistinguishable
    # from "no jobs are in that state". A typo in a filter therefore read as a
    # clean queue. See JobStatus.ALL.
    status: str | None = Query(default=None, max_length=24, pattern=r"^[a-z_]+$"),
    # Bounded at the edge, not with ``min(limit, 200)``: that let a negative
    # through, and SQLite reads ``LIMIT -1`` as unbounded, so one authenticated
    # ``?limit=-1`` serialised the entire jobs table in a single response.
    limit: int = Query(default=50, ge=1, le=200),
    # There was no offset at all. FastAPI ignores query parameters a handler
    # does not declare, so `?offset=200` was accepted and silently dropped and
    # every request returned the same newest page — 71 of the deployment's 269
    # jobs were unreachable through this endpoint at any limit.
    #
    # Bounded above as well as below: an unbounded offset reaches Postgres,
    # whose OFFSET is a bigint, and one past int64 came back as a 500. See
    # MAX_OFFSET.
    offset: int = Query(default=0, ge=0, le=MAX_OFFSET),
    # THE CURSOR, AND WHY IT EXISTS.
    #
    # OFFSET counts rows from the top, so it is only correct while the top does
    # not move. This table's whole purpose is that it moves: submissions arrive
    # continuously, retention deletes rows on a schedule, and the Queue page
    # polls every three seconds. Reproduced — seed ten jobs, read page one, let
    # ONE submission arrive, read page two: the last row of page one is the
    # first row of page two. Delete one instead and a row is served on no page
    # at all, so an analyst can page straight past a sample.
    #
    # A cursor names the last row seen instead of counting, so rows arriving
    # above it cannot shift it. `(created_at, id)` is already the sort key and
    # already a total order, which is what makes this exact rather than
    # approximate.
    #
    # `offset` stays and still works: it is in docs/api.md, and a caller who
    # wants page seven directly should not have to walk to it.
    cursor: str | None = Query(default=None, max_length=64, pattern=r"^[0-9]+(\.[0-9]+)?:[0-9]+$"),
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
):
    """One page of the queue, with the total the caller needs to page through it."""
    # A status that no job can hold is a caller mistake, not an empty result.
    # `?status=zzz` returned `200 []`, which is byte-identical to the answer for
    # `?status=failed` on a healthy deployment — so a typo in a dashboard filter
    # read as "nothing is failing". Say so instead, and name the valid values.
    if status is not None and status not in JobStatus.ALL:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Unknown status {status!r}. A job's status is one of: "
                + ", ".join(JobStatus.ALL)
            ),
        )
    conditions = _visible_jobs(identity, status)
    total = db.execute(
        select(func.count()).select_from(SandboxJob).where(*conditions)
    ).scalar_one()

    query = select(SandboxJob).where(*conditions)
    if cursor:
        seen_at, seen_id = _decode_cursor(cursor)
        # Strictly after the last row seen, in the sort's own order. A tuple
        # comparison would be neater; SQLite does not have one, so it is spelled
        # out — and spelled out it is also obvious that the tie-break is what
        # makes rows written in the same second unambiguous.
        query = query.where(
            or_(
                SandboxJob.created_at < seen_at,
                and_(SandboxJob.created_at == seen_at, SandboxJob.id < seen_id),
            )
        )
    elif offset:
        query = query.offset(offset)

    # One more row than asked for, and then discarded. "The page was full" and
    # "there is another page" are not the same thing, and guessing costs the
    # client a whole extra round trip on every walk that ends exactly on a
    # boundary — which is every walk with a fixed page size.
    rows = db.execute(
        query.order_by(SandboxJob.created_at.desc(), SandboxJob.id.desc()).limit(limit + 1)
    ).scalars().all()
    has_more = len(rows) > limit
    rows = rows[:limit]

    return JobPage(
        items=[JobSummary.of(j) for j in rows],
        total=total,
        limit=limit,
        offset=offset,
        # The cursor for the NEXT page, or None at the end. The client never
        # builds one, so the encoding is ours to change.
        next_cursor=_encode_cursor(rows[-1]) if (has_more and rows) else None,
    )


def _encode_cursor(job: SandboxJob) -> str:
    """`<created_at epoch>:<id>` — the sort key of the last row on this page."""
    created = job.created_at
    stamp = created.replace(tzinfo=timezone.utc).timestamp() if created else 0.0
    return f"{stamp:.6f}:{job.id}"


def _decode_cursor(cursor: str) -> tuple[datetime, int]:
    """Parse a cursor this endpoint issued.

    The shape is pinned by the route's `pattern`, so this cannot be reached with
    anything else — but it still refuses rather than raising, because a client
    holding yesterday's cursor after a format change deserves a 422 and not a
    500.
    """
    stamp, _sep, raw_id = cursor.partition(":")
    try:
        seen_at = datetime.fromtimestamp(float(stamp), tz=timezone.utc).replace(tzinfo=None)
        return seen_at, int(raw_id)
    except (ValueError, OverflowError, OSError) as exc:
        raise HTTPException(status_code=422, detail="Malformed page cursor") from exc


#: A verdict the engine actually issued, as opposed to the absence of one. The
#: column is JSON and may be NULL, `{}`, or hold a verdict this version does not
#: know about; only these three count as classified.
_VERDICTS = ("malicious", "suspicious", "clean")

#: Matches `needsAttention` in frontend/src/lib/format.ts. Two definitions of
#: "needs attention" is a defect waiting to happen, so this one is written to
#: mirror that one line for line: a classified job counts unless it is clean,
#: and an unclassified job counts on score alone.
_ATTENTION_FLOOR = 30.0


@router.get("/jobs/stats", response_model=JobStats)
def job_stats(
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
):
    """Counts over EVERY job in the tenant, not over one page of them.

    The dashboard computed its tiles, its donut, its family breakdown and its
    top-risk list from whatever `GET /api/jobs` returned — 50 rows, unpaged.
    Measured live: "Analysed" read 50 against 269, "Malicious" read 10 against
    151, "Needs attention" 16 against 197. Paging cannot fix it, because the
    page limit is 200 and the table is already larger; the counts have to be
    counted where the rows are.
    """
    scope = _visible_jobs(identity)
    verdict_of = SandboxJob.verdict["verdict"].as_string()
    is_done = SandboxJob.status == JobStatus.COMPLETED
    completed_scope = [*scope, is_done]

    attention = (
        verdict_of.in_(("malicious", "suspicious"))
        | (~verdict_of.in_(_VERDICTS) & (SandboxJob.final_score >= _ATTENTION_FLOOR))
        | (verdict_of.is_(None) & (SandboxJob.final_score >= _ATTENTION_FLOOR))
    )

    def _tally(condition):
        return func.sum(case((condition, 1), else_=0))

    # ONE pass over the rows for all seven figures, not seven.
    #
    # Two reasons, and the second is the one that shows on screen. Seven separate
    # statements are seven separate snapshots, so a single response could contain
    # `completed: 20` beside `needs_attention: 220` — a donut totalling one number
    # next to bars totalling another, on a deployment ingesting continuously. And
    # every one of them is O(rows): measured at 100k jobs the endpoint took about
    # a second, which the dashboard then asked for every four seconds.
    counts = db.execute(
        select(
            func.count(),
            _tally(is_done),
            _tally(SandboxJob.status.in_([JobStatus.QUEUED, JobStatus.RUNNING])),
            *[_tally(is_done & (verdict_of == name)) for name in _VERDICTS],
            _tally(is_done & attention),
            func.avg(case((is_done, SandboxJob.final_score))),
        ).where(*scope)
    ).one()
    total, done, in_flight, n_mal, n_susp, n_clean, needs_attention, average = counts

    completed = int(done or 0)
    verdicts = {
        "malicious": int(n_mal or 0),
        "suspicious": int(n_susp or 0),
        "clean": int(n_clean or 0),
    }
    #: Whatever is left: NULL verdicts, `{}`, and any verdict a later version
    #: introduces. Derived rather than counted so the four keys the UI draws
    #: always add up to `completed` — a donut that does not sum is a donut that
    #: is wrong about something.
    verdicts["unclassified"] = completed - sum(verdicts.values())

    families = [
        FamilyCount(family=name, count=int(n))
        for name, n in db.execute(
            select(SandboxJob.family, func.count())
            .where(*scope)
            .group_by(SandboxJob.family)
            .order_by(func.count().desc(), SandboxJob.family)
        ).all()
    ]

    # Verdict first, magnitude second — a malicious sample outranks a suspicious
    # one whatever their scores, which is the whole point of having a verdict.
    rank = case({"malicious": 2, "suspicious": 1}, value=verdict_of, else_=0)
    top_risk = db.execute(
        select(SandboxJob)
        .where(*completed_scope, attention)
        .order_by(rank.desc(), SandboxJob.final_score.desc(), SandboxJob.id.desc())
        .limit(5)
    ).scalars().all()

    # `average or 0.0` is not enough on its own: NaN is truthy, so a single
    # legacy row with a non-finite score would carry NaN out through the one
    # field here that is an average rather than a count — and the dashboard
    # calls `.toFixed(0)` on it, so one poisoned row blanks the whole page
    # rather than one tile. `scoring.assess` refuses to write such a row now;
    # this is what covers the ones written before it did.
    mean = float(average) if average is not None else 0.0
    if not math.isfinite(mean):
        mean = 0.0

    return JobStats(
        total=int(total or 0),
        completed=completed,
        in_flight=int(in_flight or 0),
        verdicts=verdicts,
        needs_attention=int(needs_attention or 0),
        average_score=round(mean, 1),
        families=families,
        top_risk=[JobSummary.of(j) for j in top_risk],
    )


# --- job-centric actions -----------------------------------------------------
@router.post("/jobs/{public_id}/password", response_model=JobDetail)
def provide_password(
    request: Request,
    public_id: str,
    payload: PasswordRequest,
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
):
    """Supply the password for an encrypted archive that parked itself.

    Used once, never stored. Supplying it is the deliberate analyst action the
    brief requires; the engine never brute-forces.
    """
    job = _job_or_404(db, public_id, identity)
    if job.status != JobStatus.AWAITING_PASSWORD:
        raise HTTPException(status_code=409, detail="This job is not waiting for a password")
    _trace(request, identity, audit.AuditAction.ARCHIVE_PASSWORD_SUPPLIED, public_id=job.public_id)
    submit_analysis(job.id, payload.password)
    db.refresh(job)
    return JobDetail.of(job)


@router.post("/jobs/{public_id}/reanalyze", response_model=JobDetail)
def reanalyze(
    request: Request,
    public_id: str,
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
):
    """Re-run analysis on the same quarantined bytes (e.g. after new YARA rules)."""
    job = _job_or_404(db, public_id, identity)
    if job.status == JobStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Analysis is already running")
    job.status = JobStatus.QUEUED
    db.commit()
    _trace(request, identity, audit.AuditAction.REANALYSIS_REQUESTED, public_id=job.public_id)
    submit_analysis(job.id)
    db.refresh(job)
    return JobDetail.of(job)


@router.post("/jobs/{public_id}/feedback", response_model=JobDetail)
def submit_feedback(
    request: Request,
    public_id: str,
    payload: FeedbackRequest,
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
):
    """Record an analyst's dispute of a verdict — the feedback loop the brief asks for."""
    if payload.verdict not in (Feedback.FALSE_POSITIVE, Feedback.TRUE_POSITIVE):
        raise HTTPException(
            status_code=422, detail="verdict must be false_positive or true_positive"
        )
    job = _job_or_404(db, public_id, identity)
    job.feedback = payload.verdict
    job.feedback_note = (payload.note or "")[:2000] or None
    db.commit()
    _trace(request, identity, audit.AuditAction.FEEDBACK_RECORDED, public_id=job.public_id,
           detail={"verdict": payload.verdict})
    db.refresh(job)
    return JobDetail.of(job)


# --- exports -----------------------------------------------------------------
#
# AUTHORISE, THEN RECORD. Every export below looks the job up before it writes
# anything, and the order is the point.
#
# These three used to trace first. `_trace` takes the raw `public_id` from the
# URL, so a caller could put any string there — a job belonging to another
# tenant, or one that never existed — and have it written into the chain of
# custody as `REPORT_EXPORTED / outcome=success`. Measured: one request for a
# nonexistent id produced three such entries and bumped the export metric, for a
# report that was never generated.
#
# That is worse than an access-control bug. This chain is the product's evidence
# that it can say who did what to a sample, and it was accepting attacker-chosen
# text as a successful action. A record of something that did not happen is not
# a gap in the trail, it is a false entry in it.
#
# A refused export is deliberately NOT recorded here. It would put the same
# attacker-controlled id in the same table under a different outcome, and the
# 404 already tells the caller nothing.
@router.get("/jobs/{public_id}/export.json")
def export_json(
    request: Request,
    public_id: str,
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
):
    job = _job_or_404(db, public_id, identity)
    metrics.reports_generated_total.labels(format="json").inc()
    _trace(request, identity, audit.AuditAction.REPORT_EXPORTED, public_id=job.public_id,
           detail={"format": "json"})
    return report_mod.as_json(job)


@router.get("/jobs/{public_id}/export.stix")
def export_stix(
    request: Request,
    public_id: str,
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
):
    job = _job_or_404(db, public_id, identity)
    metrics.reports_generated_total.labels(format="stix").inc()
    _trace(request, identity, audit.AuditAction.REPORT_EXPORTED, public_id=job.public_id,
           detail={"format": "stix"})
    return report_mod.as_stix(job)


@router.get("/jobs/{public_id}/export.incident")
def export_incident(
    request: Request,
    public_id: str,
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
):
    """The incident record: the same evidence laid out in the fields a regulator asks for.

    The JSON and STIX exports serve an analyst and a TIP. This one serves the
    compliance function that has 24 hours under NIS2 Article 23(4)(a) to send an
    early warning and needs the technical facts already sorted into the shape the
    notification takes. It is explicitly a draft: the fields only the entity can
    answer are emitted empty and named, and the record says on its face that it
    is not a filing.
    """
    job = _job_or_404(db, public_id, identity)
    metrics.reports_generated_total.labels(format="incident").inc()
    _trace(request, identity, audit.AuditAction.REPORT_EXPORTED, public_id=job.public_id,
           detail={"format": "incident"})
    return incident_mod.build(job)


@router.get("/jobs/{public_id}/export.pdf")
def export_pdf(
    request: Request,
    public_id: str,
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
):
    job = _job_or_404(db, public_id, identity)
    pdf = report_mod.as_pdf(job)
    metrics.reports_generated_total.labels(format="pdf").inc()
    _trace(request, identity, audit.AuditAction.REPORT_EXPORTED, public_id=public_id,
           detail={"format": "pdf"})
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": _attachment(job.original_name, job.public_id, ".pdf")},
    )


@router.get("/jobs/{public_id}/export.signed")
def export_signed(
    request: Request,
    public_id: str,
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
    settings: Settings = Depends(get_settings),
):
    """The report as evidence: engine manifest, canonical bytes, detached signature.

    The other three exports are views for a human or a TIP. This one is for a
    recipient who does not trust us — a regulator, opposing counsel, an insurer —
    and who must be able to check, offline and with no access to this system,
    that the bytes in front of them are the bytes this deployment produced. It is
    served as ordinary JSON on purpose: ``tools/verify_report.py`` re-derives the
    canonical encoding from the parsed document, so a proxy that reformats the
    response cannot break verification.

    Without a SIGNING_KEY the document is still produced in full, and says
    plainly that it is unsigned rather than implying an assurance it lacks.
    """
    job = _job_or_404(db, public_id, identity)
    envelope = attestation.attest(job, settings=settings)
    metrics.reports_generated_total.labels(
        format="signed" if envelope["signed"] else "unsigned"
    ).inc()
    # This route did not take `request` at all, so it could not call `_trace` and
    # never did. Its four siblings all record an export — and this is the one that
    # matters most: it is the copy handed to a regulator or opposing counsel, the
    # only export whose whole purpose is to be shown to someone who does not
    # trust us. "Who took the evidence copy, and when" is the first question
    # asked about it, and the chain of custody could not answer.
    _trace(request, identity, audit.AuditAction.REPORT_EXPORTED, public_id=job.public_id,
           detail={"format": "signed", "signed": bool(envelope["signed"])})
    return envelope


# Deliberately unauthenticated: a public key that only an authenticated analyst
# can fetch cannot be used by the outside party the signature exists to convince.
# It publishes nothing but the public half of a signing key.
@router.get("/attestation/pubkey")
def attestation_pubkey(settings: Settings = Depends(get_settings)):
    """This deployment's Ed25519 public key, so a recipient can verify alone."""
    return attestation.public_key_info(settings)
