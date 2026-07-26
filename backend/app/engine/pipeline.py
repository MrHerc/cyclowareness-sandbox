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
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..util import utcnow
from . import analyzers, archives, identify as identify_mod, scoring
from .contracts import AnalyzerResult, IOCs, Sample, Signal, risk_level
from .models import JobSource, JobStatus, SandboxJob
from .storage import StoredSample

logger = logging.getLogger("sandbox.pipeline")

#: How many archive members are promoted to child jobs of their own. Beyond
#: this the members are still listed in the archive facts, but not individually
#: analysed — stated in a signal rather than dropped silently.
MAX_CHILD_JOBS = 25

#: How many child jobs one submission may create across every nesting level
#: combined. The per-archive cap bounds nothing on its own, because each level
#: multiplies: a 64 KB zip of zips of zips produced 394 analyses, and a deeper
#: one recursed until db.flush() hit a RecursionError and left the job wedged at
#: status='queued' forever.
MAX_TOTAL_CHILD_JOBS = 200

#: A child job scoring at or above this is named in its parent's report. A
#: sample with no findings at all lands near 2 (the model's all-zero baseline),
#: so this separates "we found something" from "we found nothing" — it is not a
#: bar that merely-suspicious content has to clear, because the score floor in
#: run() applies regardless of whether this signal fires.
CHILD_RISK_FLOOR = 10.0


@dataclass
class _ChildBudget:
    """How many more child jobs this submission may create, at any depth.

    One object is shared by every job in a submission's tree, which is what makes
    the budget a property of the submission rather than of each archive.
    """

    remaining: int = MAX_TOTAL_CHILD_JOBS


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
    db: Session,
    job: SandboxJob,
    sample: Sample,
    password: str | None,
    *,
    depth: int,
    budget: _ChildBudget,
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
        # ran=True, deliberately. An `unavailable` result carries no signals, so
        # a container nothing could open scored as an empty file and the job
        # completed at "low" with no error: a broken py7zr call and a missing
        # `unrar` binary both presented as an all-clear. The failure to open the
        # container IS the finding, and it has to reach scoring to be seen.
        return (
            AnalyzerResult(
                analyzer="archive",
                ran=True,
                signals=[
                    Signal(
                        id="archive.not_inspected",
                        title="Container could not be inspected",
                        severity="medium",
                        detail=(
                            "This file is a container, and unpacking it failed. Nothing inside it "
                            "has been analysed, so this verdict covers the container only — treat "
                            "the contents as unexamined, not as clean."
                        ),
                        evidence={"kind": sample.mime, "error": f"{type(exc).__name__}: {exc}"[:300]},
                    )
                ],
                facts={"inspected": False, "error": f"{type(exc).__name__}: {exc}"[:300]},
            ),
            False,
        )

    members = unpacked.extracted()
    promoted = 0

    if depth >= archives.MAX_DEPTH:
        # The members are extracted and hashed above; what stops here is the
        # recursion into them. Silently stopping is the failure mode that let an
        # attacker bury a payload under enough layers to be invisible.
        unpacked.signals.append(
            Signal(
                id="archive.nesting_limit",
                title="Nested archives were not followed any deeper",
                severity="medium",
                detail=(
                    f"This container sits {depth} levels down, at the {archives.MAX_DEPTH}-level "
                    f"nesting limit. Its {len(members)} extractable member(s) were hashed but not "
                    "analysed, so anything below this point is unexamined."
                ),
                evidence={"depth": depth, "limit": archives.MAX_DEPTH, "members": len(members)},
            )
        )
        members = []

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
        if budget.remaining <= 0:
            unpacked.signals.append(
                Signal(
                    id="archive.analysis_budget_exhausted",
                    title="The submission's analysis budget ran out inside this archive",
                    severity="medium",
                    detail=(
                        f"This submission had already produced {MAX_TOTAL_CHILD_JOBS} member "
                        f"analyses when {len(members) - promoted} further member(s) were reached. "
                        "They were extracted and hashed but not analysed."
                    ),
                    evidence={"limit": MAX_TOTAL_CHILD_JOBS, "not_analysed": len(members) - promoted},
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
        budget.remaining -= 1
        run(db, child, _depth=depth + 1, _budget=budget)
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


#: Signals that mean "there is content below this point that nobody looked at".
#: A job carrying one of these is not a clean job; it is an incomplete one, and
#: that fact has to travel back up to whoever submitted the outer container.
BLIND_SPOT_SIGNALS = frozenset(
    {
        "archive.not_inspected",
        "archive.nesting_limit",
        "archive.analysis_budget_exhausted",
        "archive.members_not_analysed",
    }
)


def _descendants(db: Session, job: SandboxJob) -> list[SandboxJob]:
    """Every job below this one, at any depth.

    Direct children are not enough. Each layer of an archive scores near zero on
    its own — compressed bytes match no rule — so looking exactly one level down
    let a 68-point dropper dilute to 24 inside one zip and to 1.7 inside two. The
    subtree is bounded by MAX_TOTAL_CHILD_JOBS, so walking all of it is cheap.
    """
    out: list[SandboxJob] = []
    frontier = [job.id]
    seen = {job.id}
    while frontier:
        rows = db.query(SandboxJob).filter(SandboxJob.parent_job_id.in_(frontier)).all()
        frontier = []
        for row in rows:
            if row.id in seen:
                continue
            seen.add(row.id)
            frontier.append(row.id)
            out.append(row)
    return out


def _has_blind_spot(job: SandboxJob) -> bool:
    for payload in (job.analysis or {}).values():
        if not payload.get("ran"):
            continue
        for signal in payload.get("signals", []):
            if signal.get("id") in BLIND_SPOT_SIGNALS:
                return True
    return False


def _inherited_severity(score: float) -> str:
    """Severity of "something in here is dangerous", banded like the score itself."""
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _record_failure(db: Session, job: SandboxJob, exc: Exception) -> SandboxJob:
    """Write the failure onto the job row, even when the session is the casualty.

    A flush that raises leaves the session in a state where every later flush
    raises too. That is how jobs ended up stuck at status='queued' with
    error=NULL forever: nothing could be written, and nothing said so. One
    rollback-and-retry is enough, because after a rollback the session is usable
    again and the job row itself was committed before analysis started.
    """
    reason = f"{type(exc).__name__}: {exc}"[:1000]
    job_id = job.id
    for attempt in (0, 1):
        try:
            if attempt:
                db.rollback()
                refreshed = db.get(SandboxJob, job_id)
                if refreshed is None:
                    return job
                job = refreshed
            job.status = JobStatus.FAILED
            job.error = reason
            job.completed_at = utcnow()
            db.flush()
            return job
        except Exception:  # noqa: BLE001
            logger.exception("could not record the failure of job %s", job_id)
    return job


def run(
    db: Session,
    job: SandboxJob,
    *,
    password: str | None = None,
    _depth: int = 0,
    _budget: _ChildBudget | None = None,
) -> SandboxJob:
    """Analyse one job to completion. Synchronous; the caller decides threading.

    ``_depth`` and ``_budget`` are set only by the archive-member recursion in
    ``_archive_stage``; every job in one submission's tree shares one budget
    object. A caller that omits them is a new submission and gets a fresh one.
    """
    budget = _budget if _budget is not None else _ChildBudget()

    try:
        # Inside the try, not before it: this flush is where a poisoned session
        # or a constraint violation surfaces, and outside the try it left the row
        # at status='queued' with error=NULL and nobody ever knew the job died.
        job.status = JobStatus.RUNNING
        job.started_at = utcnow()
        job.error = None
        db.flush()

        # The quarantined path is derived from the hash, never from user input.
        from .storage import quarantine_root

        path = str(quarantine_root() / job.sha256[:2] / job.sha256)

        job.stage = "identify"
        db.flush()
        sample = _sample_from(job, path)

        job.stage = "unpack"
        db.flush()
        archive_result, awaiting = _archive_stage(
            db, job, sample, password, depth=_depth, budget=budget
        )
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

        # An archive is exactly as dangerous as its worst member, at any depth;
        # a clean container around a dropper must not read as clean.
        descendants = _descendants(db, job)
        worst = max(descendants, key=lambda d: d.final_score or 0.0, default=None)
        worst_score = (worst.final_score or 0.0) if worst is not None else 0.0
        contents_signals: list[Signal] = []

        if worst is not None and worst_score >= CHILD_RISK_FLOOR:
            contents_signals.append(
                Signal(
                    id="archive.malicious_member",
                    title="A file inside this archive scored as a risk on its own",
                    severity=_inherited_severity(worst_score),
                    detail=(
                        f"{worst.original_name or worst.sha256[:16]} scored "
                        f"{worst_score:.0f} ({worst.risk_level}). An archive is as "
                        "dangerous as what it carries."
                    ),
                    evidence={
                        "member": worst.archive_path or worst.original_name,
                        "sha256": worst.sha256,
                        "score": worst_score,
                    },
                )
            )

        # A blind spot found three levels down is still this submission's blind
        # spot. Left on the descendant alone, the submitted file showed a low
        # score and no signals at all — which is exactly the implied all-clear
        # the truncation was supposed to prevent.
        unexamined = [d for d in descendants if _has_blind_spot(d)]
        own_gap = any(s.id in BLIND_SPOT_SIGNALS for r in results if r.ran for s in r.signals)
        if unexamined and not own_gap:
            contents_signals.append(
                Signal(
                    id="archive.contents_not_examined",
                    title="Part of this archive's contents could not be examined",
                    severity="medium",
                    detail=(
                        f"{len(unexamined)} container(s) nested inside this one were not opened or "
                        "not fully analysed — a nesting limit, the submission's analysis budget, or "
                        "a container that could not be unpacked. Anything below those points is "
                        "unexamined, not clean."
                    ),
                    evidence={"containers": len(unexamined)},
                )
            )

        if contents_signals:
            results.append(
                AnalyzerResult(analyzer="archive-contents", ran=True, signals=contents_signals)
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

        # A container is at least as dangerous as the worst thing anywhere
        # inside it. Signals alone do not guarantee that — they are severity
        # bands that saturate — so each layer of zipping roughly halved the
        # score and two layers took a 68-point dropper to 1.7. The floor is what
        # makes the claim true rather than merely intended.
        if worst is not None and worst_score > assessment.final_score:
            assessment.breakdown["contents_floor"] = {
                "computed_score": assessment.final_score,
                "descendant_score": worst_score,
                "descendant": worst.archive_path or worst.original_name,
                "sha256": worst.sha256,
                "reason": (
                    "The score was raised to that of the worst file found inside this "
                    "container. A container cannot be safer than its contents."
                ),
            }
            assessment.final_score = worst_score
            assessment.risk_level = risk_level(worst_score)

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
        return _record_failure(db, job, exc)


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
