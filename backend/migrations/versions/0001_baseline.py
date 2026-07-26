"""baseline: sandbox_jobs as shipped before the CVSS/verdict/MITRE release

This revision reproduces exactly the schema that ``create_all()`` produced in
the release prior to f1e2a79. That equality is the whole point: an install from
that release has these tables already, so an operator can ``alembic stamp
0001_baseline`` it — claiming the schema without executing any DDL — and then
upgrade forward. If this revision drifted from what that release actually built,
the stamp would be a lie and the next migration would fail on a live customer
database.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-07-27
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "sandbox_jobs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("public_id", sa.String(length=36), nullable=False),
        sa.Column("source", sa.String(length=24), nullable=False),
        sa.Column("submitted_by", sa.String(length=64), nullable=True),
        sa.Column("original_name", sa.String(length=512), nullable=False),
        sa.Column("submitted_url", sa.Text(), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("md5", sa.String(length=32), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("mime", sa.String(length=128), nullable=False),
        sa.Column("magic", sa.String(length=255), nullable=False),
        sa.Column("family", sa.String(length=32), nullable=False),
        sa.Column("extension_mismatch", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("stage", sa.String(length=64), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("tiers", sa.JSON(), nullable=False),
        sa.Column("analysis", sa.JSON(), nullable=False),
        sa.Column("iocs", sa.JSON(), nullable=False),
        sa.Column("score_breakdown", sa.JSON(), nullable=False),
        sa.Column("rule_score", sa.Float(), nullable=False),
        sa.Column("ai_score", sa.Float(), nullable=False),
        sa.Column("final_score", sa.Float(), nullable=False),
        sa.Column("risk_level", sa.String(length=16), nullable=False),
        sa.Column("feedback", sa.String(length=24), nullable=True),
        sa.Column("feedback_note", sa.Text(), nullable=True),
        # Self-referential: an archive member points at the archive it came from.
        sa.Column("parent_job_id", sa.Integer(), nullable=True),
        sa.Column("archive_path", sa.Text(), nullable=True),
        sa.Column("dynamic", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["parent_job_id"], ["sandbox_jobs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    # Index names are SQLAlchemy's own auto-generated ones. They must match, or
    # autogenerate would see every index as both dropped and added.
    op.create_index("ix_sandbox_jobs_public_id", "sandbox_jobs", ["public_id"], unique=True)
    op.create_index("ix_sandbox_jobs_sha256", "sandbox_jobs", ["sha256"], unique=False)
    op.create_index("ix_sandbox_jobs_status", "sandbox_jobs", ["status"], unique=False)
    op.create_index("ix_sandbox_jobs_risk_level", "sandbox_jobs", ["risk_level"], unique=False)
    op.create_index(
        "ix_sandbox_jobs_parent_job_id", "sandbox_jobs", ["parent_job_id"], unique=False
    )
    op.create_index("ix_sandbox_jobs_created_at", "sandbox_jobs", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_sandbox_jobs_created_at", table_name="sandbox_jobs")
    op.drop_index("ix_sandbox_jobs_parent_job_id", table_name="sandbox_jobs")
    op.drop_index("ix_sandbox_jobs_risk_level", table_name="sandbox_jobs")
    op.drop_index("ix_sandbox_jobs_status", table_name="sandbox_jobs")
    op.drop_index("ix_sandbox_jobs_sha256", table_name="sandbox_jobs")
    op.drop_index("ix_sandbox_jobs_public_id", table_name="sandbox_jobs")
    op.drop_table("sandbox_jobs")
