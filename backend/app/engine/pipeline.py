"""The Cyclowareness Sandbox orchestrator: submission to verdict.

One job moves through: ingest -> identify -> unpack -> analyse -> enrich ->
score -> report. Each step writes its outcome onto the job row before the next
begins, so a job that dies half-way is inspectable rather than merely "failed",
and so the UI can show where it is while it is still moving.

Two tiers of analysis exist, and the job records which of them actually ran:

* **static** — parsers and YARA. Never executes the sample. Runs anywhere,
  including on managed hosting.
* **dynamic** — detonation, syscall tracing, the native engine. Requires a
  disposable, network-isolated VM with kernel-level control, which a managed
  PaaS does not and should not provide. It is fulfilled by an external worker
  (see native.py); when no worker has claimed the job, the tier is recorded as
  not run, with the reason.

The distinction is load-bearing. A verdict computed without dynamic analysis is
a verdict with a stated blind spot, and every report says so.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..util import utcnow
from . import analyzers, archives, identify as identify_mod, scoring
from .contracts import AnalyzerResult, IOCs, Sample, Signal
from .models import JobSource, JobStatus, SandboxJob
from .storage import StoredSample

logger = logging.getLogger("sandbox.pipeline")

#: How many archive members are promoted to child jobs of their own. Beyond
#: this the members are still listed in the archive facts, but not individually
#: analysed — stated in a signal rather than dropped silently.
MAX_CHILD_JOBS = 25


def new_job(
    db: Session,
    stored: StoredSample,
    *,
    original_name: str,
    source: str = JobSource.UPLOAD,
    submitted_url: str | None = None,
    submitted_by: str | None = None,
    parent: SandboxJob | None = None,
    archive_path: str | None = None,
) -> SandboxJob:
    job = SandboxJob(
        public_id=str(uuid.uuid4()),
        source=source,
        submitted_by=submitted_by,
        original_name=original_name[:512],
        submitted_url=submitted_url,
        sha256=stored.sha256,
        md5=stored.md5,
        size_bytes=stored.size_bytes,
        status=JobStatus.QUEUED,
        parent_job_id=parent.id if parent else None,
        archive_path=archive_path,
    )
    db.add(job)
    db.flush()
    return job


def _tier_record(static_ran: bool, analyzer_gaps: dict[str, str]) -> dict[str, Any]:
    from . import native

    dynamic_on = native.dynamic_available()
    return {
        "static": {
            "ran": static_ran,
            "detail": "Parsers and YARA. The sample is never executed.",
            "unavailable_analyzers": analyzer_gaps,
        },
        "dynamic": {
            "ran": dynamic_on,
            "detail": (
                "Detonation, syscall tracing and the native engine ran on an attached "
                "isolated worker."
                if dynamic_on
                else native.unavailable_reason()
            ),
        },
    }


def _yara_result(sample: Sample) -> AnalyzerResult:
    try:
        from . import yara_engine
    except Exception as exc:  # noqa: BLE001
        return AnalyzerResult.unavailable("yara", f"YARA tier unavailable: {type(exc).__name__}")
    try:
        return yara_engine.analyze(sample)
    except Exception as exc:  # noqa: BLE001
        logger.exception("yara tier raised")
        return AnalyzerResult.unavailable("yara", f"YARA scan raised {type(exc).__name__}")


def _sample_from(job: SandboxJob, path: str) -> Sample:
    ident = identify_mod.identify(path, job.original_name)
    job.mime = ident.mime
    job.magic = ident.magic
    job.family = ident.family
    job.extension_mismatch = 1 if ident.extension_mismatch else 0
    return Sample(
        path=path,
        size_bytes=job.size_bytes,
        sha256=job.sha256,
        md5=job.md5,
        mime=ident.mime,
        magic=ident.magic,
        claimed_extension=ident.claimed_extension,
        original_name=job.original_name,
        extension_mismatch=ident.extension_mismatch,
        family=ident.family,
    )


def _archive_stage(
    db: Session, job: SandboxJob, sample: Sample, password: str | None
) -> tuple[AnalyzerResult | None, bool]:
    """Unpack, promote members to child jobs. Returns (result, awaiting_password)."""
    if sample.mime not in archives.ARCHIVE_MIMES:
        return None, False
    # OOXML is a ZIP, but the office analyzer owns it — unpacking it as an
    # archive would bury the document's real findings under fifty XML parts.
    if sample.family == "office":
        return None, False

    try:
        unpacked = archives.unpack(sample.path, sample.mime, password)
    except archives.PasswordRequired:
        return None, True
    except Exception as exc:  # noqa: BLE001
        return (
            AnalyzerResult.unavailable("archive", f"could not be unpacked: {exc}"[:300]),
            False,
        )

    members = unpacked.extracted()
    promoted = 0
    for member in members:
        if promoted >= MAX_CHILD_JOBS:
            unpacked.signals.append(
                Signal(
                    id="archive.members_not_analysed",
                    title="Some archive members were listed but not analysed",
                    severity="info",
                    detail=(
                        f"{len(members) - promoted} member(s) beyond the {MAX_CHILD_JOBS}-member "
                        "analysis cap were extracted and hashed but not individually analysed."
                    ),
                )
            )
            break
        assert member.stored is not None
        child = new_job(
            db,
            member.stored,
            original_name=member.name.rsplit("/", 1)[-1][:512],
            source=JobSource.ARCHIVE_MEMBER,
            submitted_by=job.submitted_by,
            parent=job,
            archive_path=member.name[:1000],
        )
        run(db, child)
        promoted += 1

    return (
        AnalyzerResult(
            analyzer="archive",
            ran=True,
            signals=unpacked.signals,
            facts={
                "kind": unpacked.kind,
                "encrypted": unpacked.encrypted,
                "truncated": unpacked.truncated,
                "member_count": len(unpacked.members),
                "analysed_members": promoted,
                "members": [
                    {
                        "name": archives._safe_display_name(m.name),
                        "size": m.size,
                        "compressed_size": m.compressed_size,
                        "ratio": round(m.ratio, 1),
                        "encrypted": m.encrypted,
                        "extracted": m.stored is not None,
                        "sha256": m.stored.sha256 if m.stored else None,
                        "skipped_reason": m.skipped_reason,
                    }
                    for m in unpacked.members[:200]
                ],
            },
        ),
        False,
    )


def _worst_child(db: Session, job: SandboxJob) -> SandboxJob | None:
    children = (
        db.query(SandboxJob)
        .filter(SandboxJob.parent_job_id == job.id)
        .order_by(SandboxJob.final_score.desc())
        .all()
    )
    return children[0] if children else None


def run(db: Session, job: SandboxJob, *, password: str | None = None) -> SandboxJob:
    """Analyse one job to completion. Synchronous; the caller decides threading."""
    job.status = JobStatus.RUNNING
    job.started_at = utcnow()
    job.error = None
    db.flush()

    try:
        # The quarantined path is derived from the hash, never from user input.
        from .storage import quarantine_root

        path = str(quarantine_root() / job.sha256[:2] / job.sha256)

        job.stage = "identify"
        db.flush()
        sample = _sample_from(job, path)

        job.stage = "unpack"
        db.flush()
        archive_result, awaiting = _archive_stage(db, job, sample, password)
        if awaiting:
            job.status = JobStatus.AWAITING_PASSWORD
            job.stage = "awaiting password"
            job.completed_at = None
            db.flush()
            return job

        job.stage = "static analysis"
        db.flush()
        results = analyzers.run_all(sample, sample.family)
        results.append(_yara_result(sample))
        if archive_result is not None:
            results.append(archive_result)

        # An archive is exactly as dangerous as its worst member; a clean
        # container around a dropper must not read as clean.
        worst = _worst_child(db, job)
        if worst is not None and worst.final_score >= 30:
            results.append(
                AnalyzerResult(
                    analyzer="archive-contents",
                    ran=True,
                    signals=[
                        Signal(
                            id="archive.malicious_member",
                            title="A file inside this archive scored as a risk on its own",
                            severity="critical" if worst.final_score >= 80 else "high",
                            detail=(
                                f"{worst.original_name or worst.sha256[:16]} scored "
                                f"{worst.final_score:.0f} ({worst.risk_level}). An archive is as "
                                "dangerous as what it carries."
                            ),
                            evidence={
                                "member": worst.archive_path or worst.original_name,
                                "sha256": worst.sha256,
                                "score": worst.final_score,
                            },
                        )
                    ],
                )
            )

        job.stage = "scoring"
        db.flush()

        merged = IOCs()
        for result in results:
            if result.ran:
                merged = merged.merge(result.iocs)

        gaps = analyzers.unavailable_analyzers()
        tiers = _tier_record(static_ran=any(r.ran for r in results), analyzer_gaps=gaps)
        assessment = scoring.assess(results, ioc_total=merged.total(), tiers=tiers)

        # Real security-analyst outputs: CVSS v3.1, a VirusTotal-style internal
        # verdict, and the MITRE ATT&CK techniques the behaviour maps to. All
        # derived from the same signals — no external call, nothing fabricated.
        from . import cvss as cvss_mod, mitre as mitre_mod, verdict as verdict_mod

        all_signals = [s for r in results if r.ran for s in r.signals]
        cvss_res = cvss_mod.assess(
            sample.family, all_signals, merged, from_url=(job.source == JobSource.URL)
        )
        verdict_res = verdict_mod.classify(
            sample.family, sample.mime, results, merged, assessment.final_score
        )

        job.analysis = {r.analyzer: r.to_dict() for r in results}
        job.iocs = merged.to_dict()
        job.tiers = tiers
        job.score_breakdown = assessment.breakdown
        job.rule_score = assessment.rule_score
        job.ai_score = assessment.ai_score
        job.final_score = assessment.final_score
        job.risk_level = assessment.risk_level
        job.cvss = cvss_res.to_dict()
        job.verdict = verdict_res.to_dict()
        job.mitre = mitre_mod.map_techniques(all_signals)
        job.status = JobStatus.COMPLETED
        job.stage = "complete"
        job.completed_at = utcnow()
        db.flush()
        return job

    except Exception as exc:  # noqa: BLE001 — a failed job must stay inspectable
        logger.exception("sandbox job %s failed", job.public_id)
        job.status = JobStatus.FAILED
        job.error = f"{type(exc).__name__}: {exc}"[:1000]
        job.completed_at = utcnow()
        db.flush()
        return job


def resume_with_password(db: Session, job: SandboxJob, password: str) -> SandboxJob:
    """Re-run a job that stopped for a password. The password is never stored."""
    if job.status != JobStatus.AWAITING_PASSWORD:
        raise ValueError("job is not waiting for a password")
    return run(db, job, password=password)


def signals_of(job: SandboxJob) -> list[dict[str, Any]]:
    """Every signal across every analyzer, worst first — the report's spine."""
    from .contracts import SEVERITY_ORDER

    out: list[dict[str, Any]] = []
    for name, payload in (job.analysis or {}).items():
        if not payload.get("ran"):
            continue
        for signal in payload.get("signals", []):
            out.append({**signal, "analyzer": name})
    out.sort(key=lambda s: -SEVERITY_ORDER.get(s.get("severity", "info"), 0))
    return out
