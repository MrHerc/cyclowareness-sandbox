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
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, metrics
from ..auth import _secure_equals
from ..config import Settings, get_settings
from ..db import get_db
from ..remote import client_ip
from ..safejson import json_safe
from ..engine import identify, native, scoring
from ..engine.contracts import IOCs, AnalyzerResult, Signal
from ..engine.models import JobSource, JobStatus, SandboxJob
from ..engine.storage import quarantine_root
from .sandbox import looks_like_public_id
from ..schemas import DynamicReportIn, JobDetail

logger = logging.getLogger("sandbox.dynamic")

router = APIRouter(prefix="/api/dynamic", tags=["dynamic"])

#: Families a dynamic worker can meaningfully detonate/emulate.
#: An RTF exploit and a LNK command line are exactly what a detonation shows,
#: and both families were absent — so nine real samples were never offered.
#:
#: Defined once, in `engine.native`, because the pipeline's tier text has to
#: promise exactly what this filter offers. It used to be a second copy here,
#: and 719 completed reports promised a detonation for families this set does
#: not contain. See `native.DETONABLE_FAMILIES`.
_DYNAMIC_FAMILIES = native.DETONABLE_FAMILIES

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
    configured = settings.dynamic_worker_token.strip()
    if not configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Dynamic ingest is not enabled on this deployment (no worker token set)",
        )
    if not x_worker_token or not _secure_equals(x_worker_token.strip(), configured):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid worker token")
    return "worker"


def _dynamic_is_attributable(job: SandboxJob) -> bool:
    """Can Windows run this file at all — and so, is the observed behaviour the
    SAMPLE's rather than the guest's?

    One definition, read by two callers that must not disagree. `_needs_dynamic`
    uses it to decide whether to spend a guest; `ingest_report` uses it to decide
    whether a report that arrives anyway may raise the score. The pipeline
    computes the same predicate from `Sample`, and when this function did not
    exist `ingest_report` simply did not ask: a detonation posted for one of the
    226 already-detonated inert files re-scored the job on the guest's behaviour
    and overwrote the pipeline's correct answer with the one it had been written
    to prevent.

    Only `script` is gated. A PE, an ELF, an Office document and a PDF all have an
    execution path by construction.
    """
    if job.family != "script":
        return True
    name = (job.original_name or job.archive_path or "").rsplit("/", 1)[-1]
    extension = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
    return identify.has_execution_path(extension, job.mime or "")


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
    if job.status != JobStatus.COMPLETED or job.family not in _DYNAMIC_FAMILIES:
        return False
    # The bytes are gone, so there is nothing to detonate. Retention purges
    # the quarantined file and leaves the row, which still reads "detonation
    # has not run" -- so without this the worker is offered a job it can
    # never complete on every poll, and the queue being oldest-first, it is
    # offered FIRST.
    if job.sample_deleted_at is not None:
        return False
    # DO NOT SPEND A GUEST ON A FILE THAT CANNOT RUN.
    #
    # `identify()` puts every `text/*` mime in family `script`, so this predicate
    # was sending LICENSE files, READMEs, man pages, CA bundles, `.desktop`
    # entries and `.gitignore` to a live Windows VM. Measured: 226 such
    # detonations, at a guest and minutes each — and every one came back with
    # signals about what the GUEST did when asked to open something inert.
    # rclone's `README.html` was reported with
    # `capev2.ransomware_file_modifications`; a LICENSE file with
    # `capev2.process_creation_suspicious_location`. That is the analysis harness
    # being described, and it was scored against the sample.
    #
    # Only the `script` family is gated: a PE, an ELF, an Office document and a
    # PDF all have an execution path by construction. Static analysis still reads
    # every byte of the files this skips.
    if not _dynamic_is_attributable(job):
        return False
    return True


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
    request: Request,
    public_id: str,
    db: Session = Depends(get_db),
    _worker: str = Depends(require_worker),
):
    """Hand the quarantined bytes to the worker for detonation.

    The path is derived from the content hash, never from a submitted name, and
    the endpoint is reachable only with the worker token. A production deployment
    should upgrade this to a signed, single-use URL — noted in native.py.
    """
    # Not a UUID, no row can match — and a NUL byte here is a driver
    # ValueError rather than a miss. See `looks_like_public_id`.
    if not looks_like_public_id(public_id):
        raise HTTPException(status_code=404, detail="Job not found")
    job = db.execute(
        select(SandboxJob).where(SandboxJob.public_id == public_id)
    ).scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    path = quarantine_root() / job.sha256[:2] / job.sha256
    if not path.is_file():
        raise HTTPException(status_code=410, detail="Sample no longer in quarantine")
    # The only point at which a customer's sample LEAVES this system. Everything
    # else in the chain of custody records something done to the evidence here;
    # this hands the raw bytes to another machine, and it was the one action not
    # written down. "Was this sample ever copied off the platform, and where to"
    # is a question a data-protection review asks first, and the answer was in
    # nothing but an nginx log.
    audit.record(
        action=audit.AuditAction.SAMPLE_RELEASED_TO_WORKER,
        actor="worker",
        actor_method="worker",
        tenant=job.tenant_id,
        object_type="sample",
        object_id=job.public_id,
        source_ip=client_ip(request),
        detail={"sha256": job.sha256, "size_bytes": job.size_bytes},
    )
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


#: A detonation produces tens to hundreds of interesting events. A worker that
#: sends a hundred thousand produces an SVG with a hundred thousand circles in
#: it, which is a blank tab and a pinned CPU on the analyst's laptop.
_MAX_TIMELINE = 2000
#: Long enough for a command line, short enough that a hostile worker cannot use
#: the timeline as storage.
_MAX_TIMELINE_TEXT = 500


def _as_text(value: Any) -> str:
    """Whatever the worker sent, as something React can render."""
    if isinstance(value, str):
        return value[:_MAX_TIMELINE_TEXT]
    if value is None:
        return ""
    return repr(value)[:_MAX_TIMELINE_TEXT]


def _timeline(raw: Any) -> list[dict[str, Any]]:
    """The behaviour timeline, in the shape the graph actually draws.

    `DynamicReportIn.timeline` is `list[dict[str, Any]]`, so the worker decides
    what is in each entry — and `BehaviorGraph` renders `{kind}` straight into
    JSX. A non-string there is "Objects are not valid as a React child", which
    unmounts the whole tree: the report page for that job goes **permanently
    blank**, and so does every page the router renders after it, from a 200
    response the API accepted without complaint.

    Making the seam produce a known shape is the fix rather than making the one
    component defensive, because the same data reaches the PDF, the JSON export
    and the signed evidence, and each of those would need its own guard.
    """
    out: list[dict[str, Any]] = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        try:
            t_ms = int(float(item.get("t_ms", 0)))
        except (TypeError, ValueError, OverflowError):
            t_ms = 0
        out.append({
            "t_ms": max(0, t_ms),
            # "event" rather than "" — the graph groups into one lane per kind,
            # and an empty lane label is a row of dots against nothing.
            "kind": _as_text(item.get("kind")).strip() or "event",
            "detail": _as_text(item.get("detail")),
        })
        if len(out) >= _MAX_TIMELINE:
            break
    return out


def _static_results(job: SandboxJob) -> list[AnalyzerResult]:
    """The job's static findings, re-run against the CURRENT engine if it can be.

    Ingest used to rebuild the static half purely from the stored JSON, which
    froze it at whatever engine version first scored the sample. A detonation
    arrives minutes to days later, so the two halves of one verdict could come
    from two different builds — and an operator re-scoring their database after
    a rules change silently missed every job that happened to be in the
    detonation queue at the time.

    Measured on this deployment: a sweep re-scored 412 jobs, and
    `sample_093.msi` came back afterwards still carrying
    `generic.embedded_executable` — the exact finding that sweep existed to
    remove — because its report landed after the sweep passed it.

    The bytes are already on disk and the static tier costs milliseconds, so
    re-running it is the honest answer. Retention may have purged the sample,
    though, and a report is not worth losing over that: with no bytes, fall back
    to the stored findings. Analyzers the fresh pass does not produce — the
    archive stage's `archive` and `archive-contents`, which cost an unpack and
    would re-create child jobs — are carried over from storage either way.
    """
    stored = {
        name: payload
        for name, payload in (job.analysis or {}).items()
        if not name.startswith("dynamic.") and isinstance(payload, dict)
    }
    by_name: dict[str, AnalyzerResult] = {}

    path = quarantine_root() / job.sha256[:2] / job.sha256
    if job.sample_deleted_at is None and path.exists():
        from ..engine import analyzers
        from ..engine.pipeline import _sample_from, _yara_result

        try:
            sample = _sample_from(job, str(path))
            fresh = analyzers.run_all(sample, sample.family)
            fresh.append(_yara_result(sample))
            by_name = {r.analyzer: r for r in fresh}
        except Exception:  # noqa: BLE001
            # A failed re-run must not cost the detonation. Report it and use
            # what is on the row.
            logger.exception("static re-run failed on ingest for %s", job.public_id)
            by_name = {}

    for name, payload in stored.items():
        by_name.setdefault(name, _result_from_stored(name, payload))
    return list(by_name.values())


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
    # Not a UUID, no row can match — and a NUL byte here is a driver
    # ValueError rather than a miss. See `looks_like_public_id`.
    if not looks_like_public_id(public_id):
        raise HTTPException(status_code=404, detail="Job not found")
    job = db.execute(
        select(SandboxJob).where(SandboxJob.public_id == public_id)
    ).scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    # READ THE "BEFORE" BEFORE ANYTHING IS WRITTEN.
    #
    # These two feed the chain-of-custody entry that records what this ingest
    # changed, and they were read two hundred lines below — after
    # `job.final_score` had already been reassigned. So the single largest
    # mutation this product performs on a verdict recorded `score_before ==
    # score_after` on every row: a Formbook sample that went 32.0 -> 71.8 wrote
    # `71.8 -> 71.8`, and the audit trail said nothing had happened.
    verdict_before = (job.verdict or {}).get("verdict")
    score_before = job.final_score

    # EVERY free-form value the worker sent, made storable.
    #
    # `facts`, a signal's `evidence` and the timeline are `dict[str, Any]`, so
    # whatever the worker put there is what gets written to the row. `json.loads`
    # accepts `NaN` and `Infinity` — they are what `json.dumps` emits by default
    # — and Starlette refuses to serialise them on the way out. So one `NaN` in
    # `facts` was accepted with a 200 and then made `export.json` and
    # `export.signed` return 500 for that job permanently: the signed evidence
    # copy, unreachable, because of a number in a dict.
    #
    # This is the widest input the product takes from another machine, and it is
    # sanitised at the seam rather than at each of the places that later read it.
    dyn_signals = [
        Signal(
            id=s.id,
            title=s.title,
            severity=s.severity,
            detail=s.detail,
            evidence=json_safe(s.evidence),
        )
        for s in report.signals
    ]
    dyn_facts = json_safe(report.facts)
    dyn_timeline = _timeline(report.timeline)
    dyn_iocs = IOCs(**report.iocs.model_dump())
    dyn_result = AnalyzerResult(
        analyzer=f"dynamic.{report.engine}",
        ran=report.ran,
        unavailable_reason=report.unavailable_reason,
        signals=dyn_signals,
        facts={**dyn_facts, "engine": report.engine, "worker": report.worker},
        iocs=dyn_iocs,
        duration_ms=report.duration_ms,
    )

    # Re-run the static tier, drop any prior dynamic entry, add this one.
    results = _static_results(job)
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
        # The ENGINE, not the machine. This sentence is copied verbatim into
        # the PDF, the incident record and the signed evidence — documents that
        # leave the building — so naming the host published the hostname of the
        # machine that runs live malware for this organisation.
        or f"Detonated on the {report.engine} worker attached to this deployment.",
    }
    if report.refused:
        tiers["dynamic"]["refused"] = True

    # THE SAME ASSESSMENT THE PIPELINE WOULD HAVE MADE.
    #
    # This path re-scores a job from scratch when a report lands, and it was
    # missing `dynamic_attributable` — the one argument that exists to stop the
    # guest's behaviour being charged to a file Windows cannot run. So a report
    # arriving here overwrote the pipeline's correct score with the answer the
    # pipeline had already rejected: `capev2.ransomware_file_modifications` on a
    # README, scored.
    attributable = _dynamic_is_attributable(job)
    assessment = scoring.assess(
        results,
        ioc_total=merged.total(),
        tiers=tiers,
        family=job.family,
        dynamic_attributable=attributable,
    )
    if not attributable and report.ran:
        assessment.breakdown["dynamic_not_attributable"] = {
            # `_safe_suffix` is the same reading of the name the queue uses, and
            # it returns "" rather than the whole filename when there is no dot.
            # `rsplit(".", 1)[-1]` recorded `claimed_extension: "LICENSE"` for a
            # file the pipeline records as "".
            "claimed_extension": _safe_suffix(job.original_name),
            "mime": job.mime,
            "reason": (
                "Windows has no way to run a file of this type, so everything "
                "the guest was observed doing belongs to the guest - a default "
                "handler opening it, the agent copying it into place - and not "
                "to this sample. The behavioural findings are reported in full "
                "and excluded from the score."
            ),
        }

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
        "timeline": dyn_timeline,
        "signals": [s.to_dict() for s in dyn_signals],
        "facts": dyn_result.facts,
        "duration_ms": report.duration_ms,
    }
    # A refused sample is a hole in the evidence, not a quiet result. Recording
    # it on the job itself is what stops a live Mirai binary reading `completed`
    # / `low` with `error = NULL`, which is how all eight of them read.
    if report.refused:
        job.error = report.unavailable_reason
    else:
        # AND CLEARED WHEN THE HOLE IS FILLED.
        #
        # It was only ever written, never cleared, so a job refused once kept
        # the refusal string for ever — including after a later run detonated it
        # successfully. The report would then carry a completed detonation with
        # 54 signals beside `error: "CAPE refused the sample: Linux binaries
        # analysis isn't enabled"`, one record contradicting itself, in the
        # artifact this product signs. Live right now: 46 jobs hold that string,
        # 31 of them ELF, and a refused job can be re-detonated by public_id
        # today — `_needs_dynamic` gates only the QUEUE, not
        # `/api/dynamic/report/{public_id}`.
        #
        # Safe to clear unconditionally here: this endpoint is only reached for
        # a job the queue offered or a worker was pointed at, and both require
        # `status == COMPLETED` (see the queue filter and `_needs_dynamic`). A
        # job whose STATIC analysis failed is `FAILED`, never `COMPLETED`, so
        # the only thing `job.error` can hold at this point is a previous
        # refusal.
        job.error = None
    job.score_breakdown = assessment.breakdown
    job.rule_score = assessment.rule_score
    job.ai_score = assessment.ai_score
    job.final_score = assessment.final_score
    job.risk_level = assessment.risk_level

    # Recompute the analyst outputs now that behaviour has been folded in.
    from ..engine import impact as impact_mod, mitre as mitre_mod, verdict as verdict_mod

    all_signals = [s for r in results if r.ran for s in r.signals]
    # `from_url` is what makes Attack Vector Network for a sample the analyst
    # fetched from the internet. Omitting it here meant DETONATING a URL-delivered
    # sample LOWERED its impact rating, because this recomputation replaced the
    # pipeline's rating with one that had forgotten where the file came from.
    impact_res = impact_mod.assess(
        job.family, all_signals, merged, from_url=(job.source == JobSource.URL)
    )
    verdict_res = verdict_mod.classify(
        job.family, job.mime, results, merged, assessment.final_score
    )
    # The same rule the pipeline applies: a clean verdict rates nothing. See
    # `impact.unrated` for why the two can disagree at all.
    if verdict_res.verdict == "clean":
        impact_res = impact_mod.unrated(
            "The engine\'s verdict for this sample is clean: no finding reached "
            "the threshold to flag it, so there is no demonstrated impact to rate."
        )
    job.impact = impact_res.to_dict()
    job.verdict = verdict_res.to_dict()
    job.mitre = mitre_mod.map_techniques(all_signals)

    # AND THE CONTAINER ABOVE IT.
    #
    # pipeline.run enforces "a container carries the verdict of the worst thing
    # found in it" once, at static time. This path re-scored only the job the
    # report was posted for, so an archive member that detonated to malicious
    # left its zip reading the pre-detonation verdict for ever. That is not
    # cosmetic: /api/jobs and /api/jobs/stats both scope to parent_job_id IS
    # NULL, so the queue, the tiles and the donut see ONLY the container -- a
    # detonation-confirmed malicious sample counted as suspicious and absent
    # from the malicious total. Measured before the fix: 64 live jobs scored
    # below a detonated child.
    #
    # Not pipeline.run on the ancestor: that would re-unpack the container and
    # reset its completed_at, which is evidence.
    from ..engine import pipeline as pipeline_mod

    raised_ancestors = pipeline_mod.reapply_to_ancestors(db, job)
    if raised_ancestors:
        logger.info(
            "detonation of %s raised %d container(s) above it",
            job.public_id, raised_ancestors,
        )

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
