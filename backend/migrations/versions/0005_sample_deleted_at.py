"""Record when retention deleted a sample's bytes.

The report outlives the sample: once the retention window on the quarantined
bytes passes they are unlinked, but the verdict, signals and custody chain stay.
Without this column a reader cannot tell "we still hold the file" from "the file
is gone", and a re-analysis would fail on a missing path with no explanation.

Revision ID: 0005_sample_deleted_at
Revises: 0004_audit_events
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005_sample_deleted_at"
down_revision = "0004_audit_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Batch mode so the same migration works on SQLite, which cannot ALTER in
    # place, as well as on PostgreSQL.
    with op.batch_alter_table("sandbox_jobs") as batch:
        batch.add_column(sa.Column("sample_deleted_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("sandbox_jobs") as batch:
        batch.drop_column("sample_deleted_at")
