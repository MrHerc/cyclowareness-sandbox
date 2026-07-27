"""Data lifecycle: how long a sample and its evidence are kept, and the proof they went.

Two clocks, because the bytes and the evidence are different liabilities.

* **The sample** is live malware sitting on the operator's disk. It is a hazard
  and a storage cost, and nothing after the analysis needs it except a
  re-analysis. It goes first, and its window is short.
* **The report** — verdict, signals, impact rating, chain of custody — is the
  thing the customer bought. It is what a regulator or an auditor reads, so it
  outlives the sample and is usually kept for years.

Deleting the sample while keeping the report is therefore the normal steady
state, and the report says plainly that the bytes are gone.

Three properties this has to get right, each because getting it wrong is worse
than never sweeping at all:

1. **Content-addressed storage means one file can back many jobs.** Deleting by
   file age alone — which the previous helper did — removes bytes that another
   job still inside its own window depends on, and that job's re-analysis then
   fails with no explanation. A hash is unlinked only when every job referencing
   it is past the sample window.
2. **Deletion is audited.** "We deleted it" is a claim; a line in the hash-chained
   custody log naming what went and when is evidence. It is also the answer to
   the deletion clause in a data-processing agreement.
3. **Zero means keep.** A missing or unset policy must never delete a customer's
   evidence. Retention runs only when the operator has asked for it.
"""
from __future__ import annotations

import logging
import stat
import threading
from dataclasses import dataclass, field
from datetime import timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .config import get_settings
from .engine.models import SandboxJob
from .engine.storage import quarantine_root
from .util import utcnow

logger = logging.getLogger("sandbox.retention")


@dataclass
class SweepResult:
    """What one pass actually did. Reported to the operator, never estimated."""

    samples_deleted: int = 0
    bytes_reclaimed: int = 0
    reports_deleted: int = 0
    samples_retained_shared: int = 0
    errors: list[str] = field(default_factory=list)
    ran: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "ran": self.ran,
            "reason": self.reason,
            "samples_deleted": self.samples_deleted,
            "bytes_reclaimed": self.bytes_reclaimed,
            "reports_deleted": self.reports_deleted,
            "samples_retained_shared": self.samples_retained_shared,
            "errors": self.errors[:20],
        }


def _statement(settings) -> str:
    if settings.sample_retention_days <= 0 and settings.report_retention_days <= 0:
        return (
            "Retention is off: samples and reports are kept indefinitely. Set "
            "SAMPLE_RETENTION_DAYS to bound the malware held on disk."
        )
    parts = []
    parts.append(
        f"sample bytes are deleted after {settings.sample_retention_days} days"
        if settings.sample_retention_days > 0
        else "sample bytes are kept indefinitely"
    )
    parts.append(
        f"reports after {settings.report_retention_days} days"
        if settings.report_retention_days > 0
        else "reports are kept indefinitely"
    )
    return "; ".join(parts).capitalize() + "."


def policy() -> dict:
    """The configured policy, for /api/capabilities and the admin surface."""
    settings = get_settings()
    return {
        "sample_retention_days": settings.sample_retention_days,
        "report_retention_days": settings.report_retention_days,
        "sweep_interval_hours": settings.retention_sweep_hours,
        "enabled": settings.sample_retention_days > 0 or settings.report_retention_days > 0,
        "statement": _statement(settings),
    }


def _aware(dt):
    """SQLite hands back naive datetimes; the cutoff is timezone-aware."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _unlink(sha256: str) -> int:
    """Remove one quarantined file. Returns the bytes reclaimed."""
    if not sha256:
        return 0
    path = quarantine_root() / sha256[:2] / sha256
    if not path.is_file():
        return 0
    size = path.stat().st_size
    # Quarantined files are stored read-only; the write bit has to come back
    # before the unlink on platforms that enforce it.
    try:
        path.chmod(stat.S_IWUSR | stat.S_IRUSR)
    except OSError:
        pass
    path.unlink()
    return size


def sweep(db: Session, *, actor: str = "system") -> SweepResult:
    """Apply the retention policy once. Safe to call repeatedly."""
    settings = get_settings()
    result = SweepResult()

    sample_days = settings.sample_retention_days
    report_days = settings.report_retention_days
    if sample_days <= 0 and report_days <= 0:
        result.reason = "retention is not configured; nothing is ever deleted"
        return result

    result.ran = True
    result.reason = _statement(settings)
    now = utcnow()

    # --- sample bytes ---------------------------------------------------
    if sample_days > 0:
        cutoff = now - timedelta(days=sample_days)
        # Grouped by hash: the store is content-addressed, so the decision is
        # per FILE and one surviving reference keeps the bytes alive.
        by_hash: dict[str, list[SandboxJob]] = {}
        for job in db.execute(
            select(SandboxJob).where(SandboxJob.sample_deleted_at.is_(None))
        ).scalars():
            if job.sha256:
                by_hash.setdefault(job.sha256, []).append(job)

        for sha256, jobs in by_hash.items():
            if not all(j.created_at and _aware(j.created_at) < cutoff for j in jobs):
                result.samples_retained_shared += 1
                continue
            try:
                reclaimed = _unlink(sha256)
            except OSError as exc:
                result.errors.append(f"{sha256[:12]}: {type(exc).__name__}")
                continue
            for job in jobs:
                job.sample_deleted_at = now
            result.samples_deleted += 1
            result.bytes_reclaimed += reclaimed
            audit.record(
                action=audit.AuditAction.SAMPLE_PURGED,
                actor=actor,
                actor_method="system",
                object_type="sample",
                object_id=sha256,
                detail={
                    "bytes_reclaimed": reclaimed,
                    "jobs": [j.public_id for j in jobs][:20],
                    "policy_days": sample_days,
                },
            )
        db.commit()

    # --- reports --------------------------------------------------------
    if report_days > 0:
        cutoff = now - timedelta(days=report_days)
        doomed = [
            job
            for job in db.execute(select(SandboxJob)).scalars()
            if job.created_at and _aware(job.created_at) < cutoff
        ]
        # Children first: an archive member points at its parent, and deleting
        # the parent out from under it would orphan the row.
        doomed.sort(key=lambda j: j.parent_job_id is None)
        for job in doomed:
            try:
                _unlink(job.sha256)
            except OSError:
                pass
            public_id, sha256 = job.public_id, job.sha256
            db.delete(job)
            result.reports_deleted += 1
            audit.record(
                action=audit.AuditAction.REPORT_PURGED,
                actor=actor,
                actor_method="system",
                object_type="sample",
                object_id=public_id,
                detail={"sha256": sha256, "policy_days": report_days},
            )
        db.commit()

    return result


# --- scheduler ----------------------------------------------------------------
_thread: threading.Thread | None = None
_stop = threading.Event()


def _loop(interval_seconds: float) -> None:
    from .db import session_scope

    while not _stop.wait(interval_seconds):
        db = session_scope()
        try:
            outcome = sweep(db)
            if outcome.samples_deleted or outcome.reports_deleted:
                logger.info(
                    "retention sweep: %d samples (%d bytes), %d reports",
                    outcome.samples_deleted,
                    outcome.bytes_reclaimed,
                    outcome.reports_deleted,
                )
        except Exception:  # noqa: BLE001 — one bad sweep must not kill the thread
            logger.exception("retention sweep failed")
        finally:
            db.close()


def start_scheduler() -> bool:
    """Begin periodic sweeps. Returns False when retention is not configured.

    A daemon thread rather than an external cron entry, deliberately: this ships
    as an appliance into environments that are frequently air-gapped, and
    requiring the operator to wire up a scheduler is exactly how disks fill in
    the field.
    """
    global _thread
    settings = get_settings()
    if settings.sample_retention_days <= 0 and settings.report_retention_days <= 0:
        return False
    if _thread is not None and _thread.is_alive():
        return True
    _stop.clear()
    interval = max(1.0, settings.retention_sweep_hours) * 3600
    _thread = threading.Thread(target=_loop, args=(interval,), name="retention", daemon=True)
    _thread.start()
    logger.info("retention scheduler started (every %.1f h)", settings.retention_sweep_hours)
    return True


def stop_scheduler() -> None:
    _stop.set()
