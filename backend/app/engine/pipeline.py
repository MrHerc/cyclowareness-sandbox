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
from dataclasses import dataclass, field
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
    """What this submission may still spend, at any depth.

    One object is shared by every job in a submission's tree, which is what makes
    these budgets a property of the submission rather than of each archive.

    Two things are metered, because bounding the job count bounds neither the
    disk nor the work: 200 child jobs each unpacking their own fresh 256 MiB is
    about 51 GiB written to quarantine from one upload.
    """

    #: Child jobs left.
    remaining: int = MAX_TOTAL_CHILD_JOBS
    #: Bytes left to write while unpacking, shared across every archive below.
    expansion: archives.ExpansionBudget = field(default_factory=archives.ExpansionBudget)


def db_text(value: str | None, limit: int) -> str | None:
    """Make a caller-supplied string storable, and short enough for its column.

    PostgreSQL will not accept a NUL inside a text parameter -- the driver raises
    `ValueError` before the statement is ever sent -- so a NUL anywhere a caller
    can reach is a 500 rather than a validation error. `?status=%00` was one of
    these, the job-id path parameter was six more, and reproducing it against the
    live deployment found two writes still open:

        POST /api/analyze              filename with a NUL  -> 500
        POST /api/jobs/{id}/feedback   note with a NUL      -> 500

    The suite runs on SQLite, which stores a NUL happily, so none of it failed a
    test.

    Stripped, not refused. This is an analysis product: declining to analyse a
    sample because its NAME is odd would hand an attacker a single byte that
    avoids inspection altogether. The bytes are the evidence; the name is
    metadata.

    Only NUL. Other control characters store fine and removing them would alter
    evidence -- a submitted filename really can contain a tab.
    """
    if value is None:
        return None
    return value.replace("\x00", "")[:limit]


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
    tenant: str | None = None,
) -> SandboxJob:
    # A file extracted from an archive belongs to whoever submitted the archive,
    # never to whoever happens to be creating it. Inheriting from the parent is
    # not a convenience here — an archive member that landed in the wrong tenant
    # would be a leak nobody submitted and nobody could see coming, because the
    # unpack stage runs in the background with no request identity at all.
    if parent is not None:
        owner = parent.tenant_id
    else:
        owner = (tenant or "").strip()
    if not owner:
        raise ValueError(
            "create_job needs a tenant: pass one, or a parent to inherit from. "
            "Defaulting here would put unowned evidence in whichever tenant the "
            "default happened to be."
        )
    job = SandboxJob(
        public_id=str(uuid.uuid4()),
        tenant_id=db_text(owner, 64),
        source=source,
        # `submitted_by` is String(64) and was the only one of the three
        # not clipped, so a tenant name over 53 characters overflowed it.
        submitted_by=db_text(submitted_by, 64),
        original_name=db_text(original_name, 512) or "",
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


def _result_from_stored(name: str, payload: dict[str, Any]) -> AnalyzerResult:
    """Rebuild an AnalyzerResult from what was persisted on the job.

    Lives here rather than in the API layer so the pipeline can carry a stored
    detonation forward without the engine importing from `app.api`.
    """
    signals = [
        Signal(
            id=s.get("id", ""),
            title=s.get("title", ""),
            severity=s.get("severity", "info"),
            detail=s.get("detail", ""),
            evidence=s.get("evidence", {}) or {},
        )
        for s in payload.get("signals", []) or []
    ]
    stored_iocs = payload.get("iocs", {}) or {}
    return AnalyzerResult(
        analyzer=name,
        ran=bool(payload.get("ran", True)),
        unavailable_reason=payload.get("unavailable_reason"),
        signals=signals,
        facts=payload.get("facts", {}) or {},
        iocs=IOCs(**{f: list(stored_iocs.get(f, []) or []) for f in IOCs.FIELDS}),
        duration_ms=int(payload.get("duration_ms", 0) or 0),
    )


def _tier_record(static_ran: bool, analyzer_gaps: dict[str, str]) -> dict[str, Any]:
    from . import native

    dynamic_on = native.dynamic_available()
    return {
        "static": {
            "ran": static_ran,
            "detail": "Parsers and YARA. The sample is never executed.",
            "unavailable_analyzers": analyzer_gaps,
        },
        # NEVER True here. Static analysis has just finished; no worker has seen
        # this sample yet, and whether one is attached says nothing about whether
        # this particular job was detonated.
        #
        # It used to be `dynamic_on`, i.e. the SANDBOX_DYNAMIC_WORKER flag, which
        # produced two failures at once the moment an operator turned the feature
        # on. The report asserted "Detonation, syscall tracing and the native
        # engine ran on an attached isolated worker" for a sample nothing had
        # executed — a false statement in an artifact this product signs. And
        # because `_needs_dynamic` skips jobs whose dynamic tier already ran, the
        # job was then dropped from the worker queue, so it never would be
        # detonated. Turning the feature on switched it off and lied about it.
        #
        # The only writer permitted to set this True is `ingest_report`, which
        # has an actual worker report in hand and copies `report.ran` from it.
        "dynamic": {
            "ran": False,
            "detail": (
                "Queued for detonation on the attached isolated worker; behaviour "
                "will be merged into this report when the worker posts it."
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
        unpacked = archives.unpack(sample.path, sample.mime, password, budget.expansion)
    except archives.PasswordRequired as exc:
        # A password that did not work is an ANSWER, not a fresh prompt. Without
        # this the job simply returned to `awaiting_password` with `error` unset,
        # so the interface re-drew the same box and the analyst could not tell a
        # wrong password from a click that did nothing.
        job.error = str(exc) if exc.attempted else None
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

    # RE-ANALYSING AN ARCHIVE MUST NOT UNPACK IT TWICE.
    #
    # This stage creates a child job per member, and nothing stopped it doing so
    # again. Re-analysis is the documented way to re-run a sample after a rules
    # change — and on a container it would have doubled the tree every time: 22
    # zips of ~25 members each, so a single sweep would have manufactured ~550
    # duplicate jobs, each a second row for evidence that already existed.
    #
    # Keyed on (parent, archive_path), the pair that names one member of one
    # container. A member whose row already exists is re-analysed in place by the
    # normal path rather than cloned.
    existing = {
        row.archive_path: row
        for row in db.query(SandboxJob).filter(SandboxJob.parent_job_id == job.id).all()
        if row.archive_path
    }

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
        child = existing.get(member.name[:1000])
        if child is None:
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


#: Verdicts, worst last. Used to decide whether a container must inherit.
_VERDICT_RANK = {"clean": 0, "suspicious": 1, "malicious": 2}


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
        # And the old finish time goes with it. A re-analysis moves `started_at`
        # forward while `completed_at` still holds the PREVIOUS run's, so for the
        # second or two the job is in flight the row says it finished before it
        # started — and `export.json` now prints both. Measured during one
        # re-scoring sweep: 441 of 622 completed jobs read that way at the same
        # instant. Nothing was corrupt and it resolved as each job finished, but
        # an evidence document that can say that, ever, is one an opponent only
        # has to screenshot.
        job.completed_at = None
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

        # CARRY THE DETONATION FORWARD.
        #
        # `results` is rebuilt from the static analyzers every run, so a
        # re-analysis — new YARA rules, say — used to overwrite `job.analysis`
        # with static output alone and silently drop the `dynamic.*` entry. The
        # job then went back to `tiers.dynamic.ran = False` and lost the score
        # the behaviour had earned, while `job.dynamic` still held the report:
        # the same row saying both that it was detonated and that it was not.
        #
        # Reproduced end to end: 74.9 high -> 95.2 critical after ingest ->
        # 74.9 high after re-analysis, `status=completed`, `error=None`
        # throughout. A detonation costs a guest and four minutes and cannot be
        # recovered from the quarantined bytes without doing it again. Re-running
        # the cheap tier must not destroy the expensive one.
        for name, stored in (job.analysis or {}).items():
            if not name.startswith("dynamic.") or not isinstance(stored, dict):
                continue
            if any(r.analyzer == name for r in results):
                continue
            results.append(_result_from_stored(name, stored))

        job.stage = "scoring"
        db.flush()

        merged = IOCs()
        for result in results:
            if result.ran:
                merged = merged.merge(result.iocs)

        gaps = analyzers.unavailable_analyzers()
        tiers = _tier_record(static_ran=any(r.ran for r in results), analyzer_gaps=gaps)
        # A carried-forward detonation keeps the tier it earned. `_tier_record`
        # hard-codes `ran: False` — correctly, because a fresh static pass has
        # detonated nothing — but this job HAS been detonated, and the evidence
        # is in `results` above. Leaving the tier False would state the opposite
        # of what the same report contains.
        carried = (job.tiers or {}).get("dynamic") or {}
        if carried.get("ran") and any(
            r.analyzer.startswith("dynamic.") and r.ran for r in results
        ):
            tiers["dynamic"] = dict(carried)
        # A REFUSAL IS CARRIED INDEPENDENTLY OF `ran`, BECAUSE IT IS THE `ran:
        # False` CASE.
        #
        # The block above only carries a tier that RAN, and a refused sample by
        # definition did not. So re-analysis — the documented way to re-run a
        # sample after a rules change — erased the `refused` marker, and
        # `_needs_dynamic` reads exactly that marker to stop re-offering a sample
        # the sandbox has already declined. One re-analysis therefore reopened
        # the infinite loop it was written to close: eight ELF samples CAPE will
        # never accept, re-downloaded and re-refused on every poll, forever.
        #
        # `job.error` goes with it. It is the only place the reason is visible on
        # the job, and without it a live Mirai binary reads `completed` / `low`
        # with `error = NULL` again.
        elif carried.get("refused"):
            tiers["dynamic"]["refused"] = True
            tiers["dynamic"]["detail"] = carried.get("detail") or tiers["dynamic"]["detail"]
            if not job.error:
                job.error = carried.get("detail") or "The sandbox declined this sample."
        # A DETONATION OF SOMETHING THAT CANNOT EXECUTE OBSERVED THE GUEST.
        #
        # `_needs_dynamic` no longer sends inert files to a worker, but 226 of
        # them were already detonated and their reports are carried forward above
        # — deliberately, because a detonation costs a guest and cannot be
        # recovered from the quarantined bytes. So the evidence is kept and shown
        # in full, and simply may not accuse: rclone's `README.html` was reported
        # with `capev2.ransomware_file_modifications`, and an HTML file does not
        # encrypt anything.
        #
        # Recorded in the score breakdown rather than as a signal. A first
        # attempt added an `AnalyzerResult` named `dynamic.attribution`, which
        # the carry-forward loop above then re-imported on every re-analysis AND
        # which made `tiers["dynamic"]["ran"]` true for a job that had never been
        # detonated.
        attributable = sample.family != "script" or identify_mod.has_execution_path(
            sample.claimed_extension, sample.mime
        )
        detonated = any(r.analyzer.startswith("dynamic.") and r.ran for r in results)
        assessment = scoring.assess(
            results,
            ioc_total=merged.total(),
            tiers=tiers,
            family=sample.family,
            dynamic_attributable=attributable,
        )
        if not attributable and detonated:
            assessment.breakdown["dynamic_not_attributable"] = {
                "claimed_extension": sample.claimed_extension,
                "mime": sample.mime,
                "reason": (
                    "Windows has no way to run a file of this type, so everything "
                    "the guest was observed doing belongs to the guest - a default "
                    "handler opening it, the agent copying it into place - and not "
                    "to this sample. The behavioural findings are reported in full "
                    "and excluded from the score."
                ),
            }

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

        # Real security-analyst outputs: the Cyclowareness Impact Rating, a
        # VirusTotal-style internal verdict, and the MITRE ATT&CK techniques the
        # behaviour maps to. All derived from the same signals — no external
        # call, nothing fabricated.
        from . import impact as impact_mod, mitre as mitre_mod, verdict as verdict_mod

        all_signals = [s for r in results if r.ran for s in r.signals]
        #: A rating adopted from a member, set only by the container inheritance
        #: below. Kept as the stored dict rather than a rebuilt `ImpactRating`
        #: because that is what was measured on the member's own signals.
        impact_override: dict[str, Any] | None = None
        impact_res = impact_mod.assess(
            sample.family, all_signals, merged, from_url=(job.source == JobSource.URL)
        )
        verdict_res = verdict_mod.classify(
            sample.family, sample.mime, results, merged, assessment.final_score
        )

        # A CONTAINER IS NOT SAFER THAN WHAT IS IN IT.
        #
        # The score floor above already raises the container to its worst
        # member's number, but the VERDICT is decided from the container's own
        # capabilities — and a container has none, because carrying files is not
        # a capability. So an ISO holding a malicious dropper read `suspicious`
        # at 62.9 while the member inside it read `malicious` at the same 62.9:
        # one row of the same report contradicting the row beneath it.
        #
        # That is the direction that matters. An ISO is a standard way to get a
        # payload past mark-of-the-web precisely because the wrapper looks
        # harmless, and "suspicious" is exactly the word an analyst triages last.
        # THE WORST VERDICT, NOT THE VERDICT OF THE HIGHEST SCORE.
        #
        # This read `worst`, which is selected by SCORE — so the container took
        # the verdict of whichever member happened to score highest, not of the
        # worst member. Those are different jobs whenever a low-scoring member is
        # judged worse than a high-scoring one, which is exactly what the
        # corroboration and ambient rules produce: caddy.zip held a `clean`
        # LICENSE at 21.9 and a `suspicious` README.md at 13.0, and inherited
        # CLEAN from the LICENSE. The rule this code states in its own message —
        # "a container carries the verdict of the worst thing found in it" — was
        # not the rule it implemented.
        #
        # Ordered by (verdict rank, score) so the tie-break is still the number.
        # This can only ever RAISE a container relative to the old behaviour: the
        # worst verdict is by definition no better than any single member's. It
        # is also why improving one member could previously make a container look
        # WORSE — lowering the top scorer promoted a different member, and its
        # verdict came along.
        worst_by_verdict = max(
            descendants,
            key=lambda d: (
                _VERDICT_RANK.get((d.verdict or {}).get("verdict"), 0),
                d.final_score or 0.0,
            ),
            default=None,
        )
        worst_verdict = (
            (worst_by_verdict.verdict or {}).get("verdict")
            if worst_by_verdict is not None
            else None
        )
        if worst_verdict in _VERDICT_RANK and _VERDICT_RANK.get(
            verdict_res.verdict, 0
        ) < _VERDICT_RANK[worst_verdict]:
            named = worst_by_verdict.original_name or worst_by_verdict.sha256[:16]
            verdict_res = verdict_res.raised_to(
                worst_verdict,
                because=(
                    f"{named} inside this container was "
                    f"assessed {worst_verdict}. A container carries the verdict of the worst "
                    "thing found in it."
                ),
            )

            # AND THE IMPACT RATING, WHICH WAS LEFT BEHIND.
            #
            # The score and the verdict were both raised from the member; the
            # rating was not, and a container has no capabilities of its own, so
            # `impact.assess` returns 0.0 / "none" for it. One report therefore
            # read "Malicious, 62.9, ransomware inside" next to "Impact: 0.0 —
            # no capability was demonstrated by the evidence", which is a direct
            # contradiction and reads as the product not believing itself.
            #
            # The member's own rating is adopted rather than recomputed: it was
            # measured from that file's signals, and recomputing it here from the
            # container's signals is precisely what produces the 0.0.
            inherited = worst_by_verdict.impact or {}
            if inherited.get("severity") not in (None, "", "none"):
                impact_override = dict(inherited)
                impact_override["raised_because"] = (
                    f"This rating belongs to {named}, found inside this container. "
                    "A container has no capabilities of its own, so it is rated by "
                    "the worst thing it carries."
                )

        job.analysis = {r.analyzer: r.to_dict() for r in results}
        job.iocs = merged.to_dict()
        job.tiers = tiers
        job.score_breakdown = assessment.breakdown
        job.rule_score = assessment.rule_score
        job.ai_score = assessment.ai_score
        job.final_score = assessment.final_score
        job.risk_level = assessment.risk_level
        # A CLEAN VERDICT RATES NOTHING. `classify` has a gate `impact.assess`
        # does not — it decides `clean` from the score and the detection panel —
        # so the two disagreed on exactly the samples where nothing was found.
        if verdict_res.verdict == "clean":
            impact_res = impact_mod.unrated(
                "The engine\'s verdict for this sample is clean: no finding reached "
                "the threshold to flag it, so there is no demonstrated impact to rate."
            )
            impact_override = None
        job.impact = impact_override or impact_res.to_dict()
        job.verdict = verdict_res.to_dict()
        job.mitre = mitre_mod.map_techniques(all_signals)
        job.status = JobStatus.COMPLETED
        job.stage = "complete"
        finished = utcnow()
        job.completed_at = finished
        # Written ONCE. `completed_at` moves with every re-analysis; awareness
        # does not. See the column comment in models.py — a 2027 re-score must
        # not move a 2026 NIS2 deadline.
        if job.first_completed_at is None:
            job.first_completed_at = finished
        # The engine that reached THIS verdict, captured now rather than read at
        # export time, so a signed attestation describes the engine that produced
        # it instead of whatever is deployed when someone exports it.
        from .attestation import engine_manifest as _engine_manifest

        try:
            job.engine_manifest = _engine_manifest()
        except Exception:  # noqa: BLE001 - a manifest must never fail a verdict
            logger.warning("could not capture the engine manifest for %s", job.public_id)
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
