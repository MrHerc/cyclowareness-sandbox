"""Cyclowareness Sandbox persistence.

A new table rather than new columns on an existing one, deliberately: the
project has no migration tool yet, and `create_all()` will CREATE a table it has
never seen while silently ignoring a column added to a table it already has.
Until Alembic lands, additive-by-table is the only shape that ships safely.
"""
from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db import Base
from ..util import utcnow


class JobStatus:
    QUEUED = "queued"
    RUNNING = "running"
    #: The sample is an encrypted archive and no password was supplied. The job
    #: waits for one rather than guessing — the brief is explicit that the
    #: engine must never brute-force, and an analyst supplying a password is a
    #: deliberate act we want in the audit trail.
    AWAITING_PASSWORD = "awaiting_password"
    COMPLETED = "completed"
    FAILED = "failed"

    #: Every value a job's status can hold. Exists so a caller filtering on a
    #: status that does not exist gets told, instead of an empty page that reads
    #: like "there are none" — `?status=zzz` returned `200 []`, which is the
    #: same answer as `?status=failed` on a healthy deployment and means
    #: something completely different.
    ALL = ("queued", "running", "awaiting_password", "completed", "failed")


class JobSource:
    UPLOAD = "upload"
    URL = "url"
    #: A file found inside a submitted archive.
    ARCHIVE_MEMBER = "archive_member"


class Feedback:
    FALSE_POSITIVE = "false_positive"
    TRUE_POSITIVE = "true_positive"


class SandboxJob(Base):
    """One sample, one analysis, one auditable verdict."""

    __tablename__ = "sandbox_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: Opaque public identifier. The integer id is never exposed in a URL a
    #: submitter sees, so job counts are not a side channel.
    public_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)

    #: Which tenant owns this job. Every read is scoped to it, so this column IS
    #: the isolation boundary — a query that forgets it has no boundary at all.
    #:
    #: NOT NULL with a server default: a nullable owner is an owner nobody
    #: checks, and the one row that slips through with NULL is visible to every
    #: tenant at once. Existing rows backfill to `default_tenant`, which is where
    #: the analyst session and any bare API key also land, so a single-tenant
    #: deployment sees no change whatsoever.
    tenant_id: Mapped[str] = mapped_column(
        String(64), nullable=False, default="default", server_default="default", index=True
    )

    source: Mapped[str] = mapped_column(String(24), default=JobSource.UPLOAD)
    #: The analyst identity that submitted this sample, from the auth token.
    #: A plain string, not a foreign key: this service owns no users table —
    #: it authenticates against configured credentials and records who acted.
    submitted_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

    #: Attacker-controlled. Displayed, never used as a path.
    original_name: Mapped[str] = mapped_column(String(512), default="")
    submitted_url: Mapped[str | None] = mapped_column(Text, nullable=True)

    sha256: Mapped[str] = mapped_column(String(64), index=True, default="")
    md5: Mapped[str] = mapped_column(String(32), default="")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    mime: Mapped[str] = mapped_column(String(128), default="")
    magic: Mapped[str] = mapped_column(String(255), default="")
    family: Mapped[str] = mapped_column(String(32), default="unknown")
    extension_mismatch: Mapped[bool] = mapped_column(Integer, default=0)

    status: Mapped[str] = mapped_column(String(24), default=JobStatus.QUEUED, index=True)
    stage: Mapped[str] = mapped_column(String(64), default="")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: Which analysis tiers actually ran, and which did not and why. This is the
    #: difference between "clean" and "we could not look", and the UI states it.
    tiers: Mapped[dict] = mapped_column(JSON, default=dict)
    #: Every AnalyzerResult, keyed by analyzer name.
    analysis: Mapped[dict] = mapped_column(JSON, default=dict)
    #: Merged, de-duplicated indicators across all analyzers.
    iocs: Mapped[dict] = mapped_column(JSON, default=dict)
    #: The full scoring explanation: which signals fired, what each contributed.
    score_breakdown: Mapped[dict] = mapped_column(JSON, default=dict)

    rule_score: Mapped[float] = mapped_column(Float, default=0.0)
    ai_score: Mapped[float] = mapped_column(Float, default=0.0)
    final_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(16), default="low", index=True)

    #: Set when an analyst disputes the verdict; drives the reanalysis queue.
    feedback: Mapped[str | None] = mapped_column(String(24), nullable=True)
    feedback_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: Archive members point at the archive they came out of.
    parent_job_id: Mapped[int | None] = mapped_column(
        ForeignKey("sandbox_jobs.id"), nullable=True, index=True
    )
    #: Path within the parent archive, for the tree view.
    archive_path: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: How the dynamic tier (native engine / attached sandbox) resolved for this
    #: job: the worker's own report, merged back in the same Signal vocabulary.
    dynamic: Mapped[dict] = mapped_column(JSON, default=dict)

    #: When retention deleted the quarantined bytes. The report outlives the
    #: sample, so this is how a reader tells "we still hold the file" from "the
    #: file is gone and this record is what remains of it" — and it is why
    #: re-analysis can refuse cleanly instead of failing on a missing path.
    sample_deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    #: Cyclowareness Impact Rating vector + base score (see engine/impact.py).
    #: Renamed from `cvss` by 0003; the rename carries the existing values, so a
    #: row rated by the previous release still renders.
    impact: Mapped[dict] = mapped_column(JSON, default=dict)
    #: Internal multi-engine (VirusTotal-style) verdict + threat name.
    verdict: Mapped[dict] = mapped_column(JSON, default=dict)
    #: MITRE ATT&CK techniques the observed behaviour maps to.
    mitre: Mapped[list] = mapped_column(JSON, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    #: When THIS analysis run finished. Cleared and rewritten by a re-analysis.
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    #: When this sample was FIRST assessed, written once and never again.
    #:
    #: `completed_at` moves every time the job is re-scored, which is correct for
    #: "when did this run end" and wrong for the only thing the regulation asks:
    #: NIS2 Article 23(4)(a) starts its 24-hour clock at AWARENESS, and awareness
    #: happened once. Re-scoring a job in 2027 must not move a 2026 deadline.
    first_completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    #: The engine manifest as it stood when the verdict was reached.
    #:
    #: The signed attestation used to read the manifest at EXPORT time, so a
    #: report exported today described today's engine rather than the one that
    #: produced the verdict — every rule change since silently rewriting history
    #: inside a document whose whole purpose is that it cannot be.
    engine_manifest: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Self-referential one-to-many: a parent archive job has many member jobs.
    # remote_side belongs on the MANY-TO-ONE side (parent), so the relationship
    # is declared from the child up and children is its back-reference.
    parent: Mapped["SandboxJob | None"] = relationship(
        "SandboxJob",
        remote_side=[id],
        back_populates="children",
        viewonly=True,
    )
    children: Mapped[list["SandboxJob"]] = relationship(
        "SandboxJob",
        back_populates="parent",
        viewonly=True,
    )

    @property
    def duration_ms(self) -> int | None:
        if not self.started_at or not self.completed_at:
            return None
        return int((self.completed_at - self.started_at).total_seconds() * 1000)
