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

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from .. import audit, metrics, sovereignty
from ..auth import Identity, require_analyst
from ..config import Settings, get_settings
from ..db import get_db
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
        source_ip=request.client.host if request.client else None,
        detail=detail,
    )


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
    status: str | None = None,
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
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
):
    """One page of the queue, with the total the caller needs to page through it."""
    conditions = _visible_jobs(identity, status)
    total = db.execute(
        select(func.count()).select_from(SandboxJob).where(*conditions)
    ).scalar_one()
    rows = db.execute(
        select(SandboxJob)
        .where(*conditions)
        .order_by(SandboxJob.created_at.desc(), SandboxJob.id.desc())
        .limit(limit)
        .offset(offset)
    ).scalars().all()
    return JobPage(
        items=[JobSummary.of(j) for j in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


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
    #: NULL and unknown verdicts collapse to one bucket, so the four keys the UI
    #: draws always add up to `completed`.
    bucket = case(
        {v: v for v in _VERDICTS}, value=verdict_of, else_="unclassified"
    )
    completed_scope = [*scope, SandboxJob.status == JobStatus.COMPLETED]

    total = db.execute(
        select(func.count()).select_from(SandboxJob).where(*scope)
    ).scalar_one()
    in_flight = db.execute(
        select(func.count()).select_from(SandboxJob).where(
            *scope, SandboxJob.status.in_([JobStatus.QUEUED, JobStatus.RUNNING])
        )
    ).scalar_one()

    counted = dict(
        db.execute(
            select(bucket, func.count()).where(*completed_scope).group_by(bucket)
        ).all()
    )
    verdicts = {k: int(counted.get(k, 0)) for k in (*_VERDICTS, "unclassified")}
    completed = sum(verdicts.values())

    attention = (
        verdict_of.in_(("malicious", "suspicious"))
        | (~verdict_of.in_(_VERDICTS) & (SandboxJob.final_score >= _ATTENTION_FLOOR))
        | (verdict_of.is_(None) & (SandboxJob.final_score >= _ATTENTION_FLOOR))
    )
    needs_attention = db.execute(
        select(func.count()).select_from(SandboxJob).where(*completed_scope, attention)
    ).scalar_one()
    average = db.execute(
        select(func.avg(SandboxJob.final_score)).where(*completed_scope)
    ).scalar()

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

    return JobStats(
        total=total,
        completed=completed,
        in_flight=in_flight,
        verdicts=verdicts,
        needs_attention=needs_attention,
        average_score=round(float(average or 0.0), 1),
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
    safe = "".join(c for c in (job.original_name or "report") if c.isalnum() or c in "._-")[:60]
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="sandbox-{safe or job.public_id}.pdf"'},
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
