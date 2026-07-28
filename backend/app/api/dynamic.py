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
import re

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, metrics
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

#: THIS SEAM IS DEPLOYMENT-WIDE, NOT TENANT-SCOPED, ON PURPOSE.
#:
#: The queue hands out jobs from every tenant and the report endpoint accepts a
#: result for any job, because the worker is not a tenant — it is the operator's
#: own detonation hardware, authenticated by DYNAMIC_WORKER_TOKEN, and it exists
#: to run samples for all of them. Scoping it per tenant would mean one worker
#: and one set of guests per customer, which is a different product.
#:
#: So what a stolen worker token buys is the whole deployment rather than one
#: tenant: every sample's bytes, and the ability to fabricate behaviour for any
#: job. That blast radius is unchanged by tenancy — but it does make this the
#: widest credential in the system, and it should be treated as such.


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
    dynamic = tiers.get("dynamic") or {}
    if dynamic.get("ran"):
        return False
    # A sandbox that declined this sample will decline it again — the request is
    # byte-identical. Without this, eight ELF samples CAPE refused (it has Linux
    # analysis disabled and only Windows guests) were re-downloaded, re-submitted
    # and re-refused on every single poll, forever, while each job read
    # `completed` with no error recorded.
    if dynamic.get("refused"):
        return False
    return job.status == JobStatus.COMPLETED and job.family in _DYNAMIC_FAMILIES


#: A file extension, and nothing else: one dot, then 1-8 ASCII alphanumerics.
_SUFFIX_RE = re.compile(r"^[A-Za-z0-9]{1,8}$")


def _safe_suffix(original_name: str | None) -> str:
    """The submitted name's extension, sanitised — or "" if there isn't a sane one.

    This exists because a detonation sandbox chooses how to *run* a sample from
    its file name. CAPEv2 handed a ".sample" falls back to its `generic` package;
    measured on this deployment, that turned a 229s / 4-process / 38-signature
    PowerShell detonation into a 28s / 1-process / 8-signature one. Nothing
    errored — the behavioural evidence was just quietly much thinner.

    The extension is the only part of an attacker-controlled string we propagate,
    and only when it matches ``_SUFFIX_RE``: no dots, separators, spaces or
    non-ASCII survive, so nothing here can climb a path or smuggle a second
    extension past the sandbox's own parsing.
    """
    if not original_name or "." not in original_name:
        return ""
    ext = original_name.rsplit(".", 1)[1]
    # fullmatch, not match: in Python `$` also matches immediately before a
    # trailing newline, so `_safe_suffix("invoice.exe\n")` returned ".exe\n" —
    # a newline in a value that goes on to build a Content-Disposition header
    # and a file name on the worker's disk.
    return f".{ext.lower()}" if _SUFFIX_RE.fullmatch(ext) else ""


@router.get("/queue")
def dynamic_queue(
    limit: int = 20,
    db: Session = Depends(get_db),
    _worker: str = Depends(require_worker),
):
    """Completed jobs whose dynamic tier has not run yet — the worker's work list.

    Two things here are load-bearing and both were wrong.

    **Oldest first.** Newest-first starves a backlog under sustained submission:
    freshly finished jobs keep arriving at the head of the queue and anything
    that missed its turn is never offered again.

    **Filter, then limit.** `_needs_dynamic` reads a JSON column, so it runs in
    Python — and applying `LIMIT` in SQL first meant the endpoint fetched N rows,
    discarded the ones already detonated, and returned whatever was left. Once
    the newest N had all run it returned an EMPTY queue while the backlog sat
    untouched. Measured on this deployment: 71 jobs with `dynamic.ran = false`,
    and the worker being told there was no work. Nothing errored; the pipeline
    simply stopped.

    So scan in pages until `limit` jobs are found or the table is exhausted, with
    a hard ceiling on how far to look so one poll cannot walk a huge table.
    """
    wanted = min(max(limit, 1), 100)
    #: How many rows to consider at most. A worker polls every few seconds, so a
    #: page it cannot fill this time it fills on the next one.
    SCAN_CEILING = 2000
    PAGE = 200

    candidates: list[SandboxJob] = []
    offset = 0
    while len(candidates) < wanted and offset < SCAN_CEILING:
        page = db.execute(
            select(SandboxJob)
            .where(SandboxJob.status == JobStatus.COMPLETED)
            .where(SandboxJob.family.in_(tuple(_DYNAMIC_FAMILIES)))
            .order_by(SandboxJob.created_at.asc())
            .offset(offset)
            .limit(PAGE)
        ).scalars().all()
        if not page:
            break
        candidates.extend(j for j in page if _needs_dynamic(j))
        offset += PAGE

    return [
        {
            "public_id": j.public_id,
            "sha256": j.sha256,
            "family": j.family,
            "size_bytes": j.size_bytes,
            "sample_url": f"/api/dynamic/sample/{j.public_id}",
            # So the worker can write the sample to a path the sandbox will
            # recognise. See _safe_suffix.
            "suffix": _safe_suffix(j.original_name),
        }
        for j in candidates[:wanted]
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
        # Content hash plus the sanitised original extension — never the
        # submitted string. The extension is load-bearing for the sandbox's
        # package selection; see _safe_suffix.
        filename=f"{job.sha256}{_safe_suffix(job.original_name)}",
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
    if report.refused:
        tiers["dynamic"]["refused"] = True

    assessment = scoring.assess(results, ioc_total=merged.total(), tiers=tiers)

    job.analysis = {r.analyzer: r.to_dict() for r in results}
    job.iocs = merged.to_dict()
    job.tiers = tiers
    job.dynamic = {
        "engine": report.engine,
        "worker": report.worker,
        "ran": report.ran,
        # Without this the reason existed only in `tiers`, and the field the UI
        # and the exports read said nothing at all: eight refused samples showed
        # `{"ran": false, "signals": []}` and were indistinguishable from a
        # detonation that observed nothing.
        "unavailable_reason": report.unavailable_reason,
        "refused": bool(report.refused),
        "timeline": report.timeline,
        "signals": [s.to_dict() for s in dyn_signals],
        "facts": dyn_result.facts,
        "duration_ms": report.duration_ms,
    }
    # A refused sample is a hole in the evidence, not a quiet result. Recording
    # it on the job itself is what stops a live Mirai binary reading `completed`
    # / `low` with `error = NULL`, which is how all eight of them read.
    if report.refused:
        job.error = report.unavailable_reason
    job.score_breakdown = assessment.breakdown
    job.rule_score = assessment.rule_score
    job.ai_score = assessment.ai_score
    job.final_score = assessment.final_score
    job.risk_level = assessment.risk_level

    # Recompute the analyst outputs now that behaviour has been folded in.
    from ..engine import impact as impact_mod, mitre as mitre_mod, verdict as verdict_mod

    all_signals = [s for r in results if r.ran for s in r.signals]
    verdict_before = (job.verdict or {}).get("verdict")
    score_before = job.final_score
    job.impact = impact_mod.assess(job.family, all_signals, merged).to_dict()
    job.verdict = verdict_mod.classify(job.family, job.mime, results, merged, assessment.final_score).to_dict()
    job.mitre = mitre_mod.map_techniques(all_signals)
    db.commit()
    db.refresh(job)

    # THE CHAIN OF CUSTODY HAS TO SEE THIS.
    #
    # `AuditAction.DYNAMIC_REPORT_INGESTED` was defined and had zero callers, so
    # the single largest mutation this product performs on a verdict left no
    # trace at all. A Formbook sample went from `suspicious / Win32.Clean / 32.0`
    # to `malicious / Win32.Injector.Formbook / 71.8` on the strength of a report
    # posted by an off-host machine — and the trail an auditor reads said only
    # that a sample had been submitted.
    #
    # It is recorded from the JOB's tenant, never from anything the worker sent:
    # the worker is shared infrastructure holding one token for every tenant, and
    # letting it name the tenant would let it write into any customer's history.
    audit.record(
        action=audit.AuditAction.DYNAMIC_REPORT_INGESTED,
        actor=f"worker:{report.worker}"[:128],
        actor_method="worker",
        tenant=job.tenant_id,
        object_type="sample",
        object_id=job.public_id,
        detail={
            "engine": report.engine,
            "ran": bool(report.ran),
            "refused": bool(report.refused),
            "signals": len(dyn_signals),
            "duration_ms": report.duration_ms,
            # What actually changed. "The verdict moved and here is from what to
            # what" is the question an auditor asks about an automated decision.
            "verdict_before": verdict_before,
            "verdict_after": (job.verdict or {}).get("verdict"),
            "score_before": round(float(score_before or 0), 1),
            "score_after": round(float(job.final_score or 0), 1),
            "unavailable_reason": report.unavailable_reason,
        },
    )

    metrics.dynamic_reports_total.labels(engine=report.engine).inc()
    logger.info("dynamic report ingested for %s from %s", public_id, report.engine)
    return JobDetail.of(job)
