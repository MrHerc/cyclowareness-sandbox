"""The dynamic tier's HTTP seam.

The web application never detonates anything (see ``engine/native.py`` for why).
Instead it defines the contract an off-host worker fulfils:

    GET  /api/dynamic/queue          -> jobs awaiting behavioural analysis
    GET  /api/dynamic/sample/{id}    -> the quarantined bytes to detonate
    POST /api/dynamic/report/{id}    -> the worker's findings, merged + re-scored

The worker runs on hardware the operator controls (a Firejail/seccomp jail, a
Qiling emulator, a snapshotted VM behind a sinkhole). It authenticates with a
shared token, never an analyst session — it is infrastructure, not a user. When
no token is configured the whole seam is closed: dynamic ingest is opt-in,
because accepting externally-supplied "behaviour" into a verdict is a trust
decision the operator must make deliberately.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import metrics
from ..config import Settings, get_settings
from ..db import get_db
from ..engine import scoring
from ..engine.contracts import IOCs, AnalyzerResult, Signal
from ..engine.models import JobStatus, SandboxJob
from ..engine.storage import quarantine_root
from ..schemas import DynamicReportIn, JobDetail

logger = logging.getLogger("sandbox.dynamic")

router = APIRouter(prefix="/api/dynamic", tags=["dynamic"])

#: Families a dynamic worker can meaningfully detonate/emulate.
_DYNAMIC_FAMILIES = {"pe", "elf", "script", "office", "pdf"}


def require_worker(
    x_worker_token: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> str:
    import hmac

    configured = settings.dynamic_worker_token.strip()
    if not configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Dynamic ingest is not enabled on this deployment (no worker token set)",
        )
    if not x_worker_token or not hmac.compare_digest(x_worker_token.strip(), configured):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid worker token")
    return "worker"


def _needs_dynamic(job: SandboxJob) -> bool:
    tiers = job.tiers or {}
    if (tiers.get("dynamic") or {}).get("ran"):
        return False
    return job.status == JobStatus.COMPLETED and job.family in _DYNAMIC_FAMILIES


@router.get("/queue")
def dynamic_queue(
    limit: int = 20,
    db: Session = Depends(get_db),
    _worker: str = Depends(require_worker),
):
    """Completed jobs whose dynamic tier has not run yet — the worker's work list."""
    candidates = db.execute(
        select(SandboxJob)
        .where(SandboxJob.status == JobStatus.COMPLETED)
        .where(SandboxJob.family.in_(tuple(_DYNAMIC_FAMILIES)))
        .order_by(SandboxJob.created_at.desc())
        .limit(min(limit, 100))
    ).scalars().all()
    return [
        {
            "public_id": j.public_id,
            "sha256": j.sha256,
            "family": j.family,
            "size_bytes": j.size_bytes,
            "sample_url": f"/api/dynamic/sample/{j.public_id}",
        }
        for j in candidates
        if _needs_dynamic(j)
    ]


@router.get("/sample/{public_id}")
def dynamic_sample(
    public_id: str,
    db: Session = Depends(get_db),
    _worker: str = Depends(require_worker),
):
    """Hand the quarantined bytes to the worker for detonation.

    The path is derived from the content hash, never from a submitted name, and
    the endpoint is reachable only with the worker token. A production deployment
    should upgrade this to a signed, single-use URL — noted in native.py.
    """
    job = db.execute(
        select(SandboxJob).where(SandboxJob.public_id == public_id)
    ).scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    path = quarantine_root() / job.sha256[:2] / job.sha256
    if not path.is_file():
        raise HTTPException(status_code=410, detail="Sample no longer in quarantine")
    return FileResponse(
        str(path),
        media_type="application/octet-stream",
        filename=f"{job.sha256}.sample",
    )


def _result_from_stored(name: str, payload: dict) -> AnalyzerResult:
    signals = [
        Signal(
            id=s.get("id", ""),
            title=s.get("title", ""),
            severity=s.get("severity", "info"),
            detail=s.get("detail", ""),
            evidence=s.get("evidence", {}) or {},
        )
        for s in payload.get("signals", [])
    ]
    iocs_dict = payload.get("iocs", {}) or {}
    iocs = IOCs(**{f: list(iocs_dict.get(f, []) or []) for f in IOCs.FIELDS})
    return AnalyzerResult(
        analyzer=name,
        ran=bool(payload.get("ran", True)),
        unavailable_reason=payload.get("unavailable_reason"),
        signals=signals,
        facts=payload.get("facts", {}) or {},
        iocs=iocs,
        duration_ms=int(payload.get("duration_ms", 0) or 0),
    )


@router.post("/report/{public_id}", response_model=JobDetail)
def ingest_report(
    public_id: str,
    report: DynamicReportIn,
    db: Session = Depends(get_db),
    _worker: str = Depends(require_worker),
):
    """Merge a worker's behavioural findings into the job and re-score.

    A dynamic finding scores, exports and displays exactly like a static one,
    because it arrives in the same Signal vocabulary. The score can only move —
    behaviour is evidence the static tier did not have.
    """
    job = db.execute(
        select(SandboxJob).where(SandboxJob.public_id == public_id)
    ).scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    dyn_signals = [
        Signal(id=s.id, title=s.title, severity=s.severity, detail=s.detail, evidence=s.evidence)
        for s in report.signals
    ]
    dyn_iocs = IOCs(**report.iocs.model_dump())
    dyn_result = AnalyzerResult(
        analyzer=f"dynamic.{report.engine}",
        ran=report.ran,
        unavailable_reason=report.unavailable_reason,
        signals=dyn_signals,
        facts={**report.facts, "engine": report.engine, "worker": report.worker},
        iocs=dyn_iocs,
        duration_ms=report.duration_ms,
    )

    # Rebuild the static results, drop any prior dynamic entry, add this one.
    results = [
        _result_from_stored(name, payload)
        for name, payload in (job.analysis or {}).items()
        if not name.startswith("dynamic.")
    ]
    results.append(dyn_result)

    merged = IOCs()
    for result in results:
        if result.ran:
            merged = merged.merge(result.iocs)

    tiers = dict(job.tiers or {})
    tiers["dynamic"] = {
        "ran": report.ran,
        "engine": report.engine,
        "worker": report.worker,
        "detail": report.unavailable_reason
        or f"Detonated on the {report.engine} worker ({report.worker}).",
    }

    assessment = scoring.assess(results, ioc_total=merged.total(), tiers=tiers)

    job.analysis = {r.analyzer: r.to_dict() for r in results}
    job.iocs = merged.to_dict()
    job.tiers = tiers
    job.dynamic = {
        "engine": report.engine,
        "worker": report.worker,
        "ran": report.ran,
        "timeline": report.timeline,
        "signals": [s.to_dict() for s in dyn_signals],
        "facts": dyn_result.facts,
        "duration_ms": report.duration_ms,
    }
    job.score_breakdown = assessment.breakdown
    job.rule_score = assessment.rule_score
    job.ai_score = assessment.ai_score
    job.final_score = assessment.final_score
    job.risk_level = assessment.risk_level

    # Recompute the analyst outputs now that behaviour has been folded in.
    from ..engine import cvss as cvss_mod, mitre as mitre_mod, verdict as verdict_mod

    all_signals = [s for r in results if r.ran for s in r.signals]
    job.cvss = cvss_mod.assess(job.family, all_signals, merged).to_dict()
    job.verdict = verdict_mod.classify(job.family, job.mime, results, merged, assessment.final_score).to_dict()
    job.mitre = mitre_mod.map_techniques(all_signals)
    db.commit()
    db.refresh(job)

    metrics.dynamic_reports_total.labels(engine=report.engine).inc()
    logger.info("dynamic report ingested for %s from %s", public_id, report.engine)
    return JobDetail.of(job)
