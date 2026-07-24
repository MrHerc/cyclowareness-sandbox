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

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import metrics
from ..auth import Identity, require_analyst
from ..config import Settings, get_settings
from ..db import get_db
from ..engine import pipeline
from ..engine import report as report_mod
from ..engine.fetcher import FetchFailed, UnsafeURL, fetch
from ..engine.models import Feedback, JobSource, JobStatus, SandboxJob
from ..engine.storage import EmptySample, SampleTooLarge, store_stream
from ..runner import submit_analysis
from ..schemas import (
    FeedbackRequest,
    JobDetail,
    JobSummary,
    PasswordRequest,
    SubmitURLRequest,
)

logger = logging.getLogger("sandbox.api")

router = APIRouter(prefix="/api", tags=["analysis"])


def _max_bytes(settings: Settings) -> int:
    return max(1, settings.max_sample_mb) * 1024 * 1024


def _job_or_404(db: Session, public_id: str) -> SandboxJob:
    job = db.execute(
        select(SandboxJob).where(SandboxJob.public_id == public_id)
    ).scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    return job


# --- submission --------------------------------------------------------------
@router.post("/analyze", response_model=JobDetail, status_code=201)
async def analyze(
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
    )
    db.commit()
    metrics.uploads_total.labels(source="upload").inc()
    submit_analysis(job.id, password)
    db.refresh(job)
    return JobDetail.of(job)


@router.post("/analyze/url", response_model=JobDetail, status_code=201)
def analyze_url(
    payload: SubmitURLRequest,
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
    settings: Settings = Depends(get_settings),
):
    """Submit a URL. The server downloads it — after refusing to fetch anything
    that resolves to a private, loopback or cloud-metadata address (SSRF guard)."""
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
    )
    db.commit()
    metrics.uploads_total.labels(source="url").inc()
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
    job = _job_or_404(db, public_id)
    children = db.execute(
        select(SandboxJob)
        .where(SandboxJob.parent_job_id == job.id)
        .order_by(SandboxJob.final_score.desc())
    ).scalars().all()
    return JobDetail.of(job, children=children)


@router.get("/jobs", response_model=list[JobSummary])
def list_jobs(
    status: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
):
    query = (
        select(SandboxJob)
        # Top-level jobs only; archive members are shown nested under their parent.
        .where(SandboxJob.parent_job_id.is_(None))
        .order_by(SandboxJob.created_at.desc())
        .limit(min(limit, 200))
    )
    if status:
        query = query.where(SandboxJob.status == status)
    return [JobSummary.of(j) for j in db.execute(query).scalars().all()]


# --- job-centric actions -----------------------------------------------------
@router.post("/jobs/{public_id}/password", response_model=JobDetail)
def provide_password(
    public_id: str,
    payload: PasswordRequest,
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
):
    """Supply the password for an encrypted archive that parked itself.

    Used once, never stored. Supplying it is the deliberate analyst action the
    brief requires; the engine never brute-forces.
    """
    job = _job_or_404(db, public_id)
    if job.status != JobStatus.AWAITING_PASSWORD:
        raise HTTPException(status_code=409, detail="This job is not waiting for a password")
    submit_analysis(job.id, payload.password)
    db.refresh(job)
    return JobDetail.of(job)


@router.post("/jobs/{public_id}/reanalyze", response_model=JobDetail)
def reanalyze(
    public_id: str,
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
):
    """Re-run analysis on the same quarantined bytes (e.g. after new YARA rules)."""
    job = _job_or_404(db, public_id)
    if job.status == JobStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Analysis is already running")
    job.status = JobStatus.QUEUED
    db.commit()
    submit_analysis(job.id)
    db.refresh(job)
    return JobDetail.of(job)


@router.post("/jobs/{public_id}/feedback", response_model=JobDetail)
def submit_feedback(
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
    job = _job_or_404(db, public_id)
    job.feedback = payload.verdict
    job.feedback_note = (payload.note or "")[:2000] or None
    db.commit()
    db.refresh(job)
    return JobDetail.of(job)


# --- exports -----------------------------------------------------------------
@router.get("/jobs/{public_id}/export.json")
def export_json(
    public_id: str,
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
):
    metrics.reports_generated_total.labels(format="json").inc()
    return report_mod.as_json(_job_or_404(db, public_id))


@router.get("/jobs/{public_id}/export.stix")
def export_stix(
    public_id: str,
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
):
    metrics.reports_generated_total.labels(format="stix").inc()
    return report_mod.as_stix(_job_or_404(db, public_id))


@router.get("/jobs/{public_id}/export.pdf")
def export_pdf(
    public_id: str,
    db: Session = Depends(get_db),
    identity: Identity = Depends(require_analyst),
):
    job = _job_or_404(db, public_id)
    pdf = report_mod.as_pdf(job)
    metrics.reports_generated_total.labels(format="pdf").inc()
    safe = "".join(c for c in (job.original_name or "report") if c.isalnum() or c in "._-")[:60]
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="sandbox-{safe or job.public_id}.pdf"'},
    )
