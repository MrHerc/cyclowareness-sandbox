"""Pin the awareness time and the engine that reached the verdict.

Two evidence defects, both about a record that changes after the fact.

**`first_completed_at`.** `completed_at` is deliberately cleared and rewritten by
every re-analysis — a re-run that left the old finish time in place made 441 of
622 jobs read "finished before it started" for the seconds they were in flight.
That is right for "when did this ANALYSIS end", and wrong for the only thing the
regulation cares about: NIS2 Article 23(4)(a) starts its 24-hour clock at
AWARENESS, and awareness happened once, the first time this sample was assessed.
Re-scoring a job in 2027 must not move a 2026 deadline.

**`engine_manifest`.** The manifest inside a signed attestation was read at
EXPORT time, so a report exported today described the engine as it is today, not
as it was when the verdict was reached. Every rule change since silently
rewrote history in a document whose entire purpose is that it cannot be. Captured
at verdict time now; exports fall back to the live manifest for rows written
before this migration and say which one they used.

Both are nullable and backfilled from what is already known: `first_completed_at`
from the existing `completed_at`, which for a job that has never been re-analysed
IS the first completion. Rows that were re-analysed before this migration keep
the best available answer and nothing pretends otherwise.

Revision ID: 0007_evidence_time
Revises: 0006_tenant_id
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

#: KEEP THIS UNDER 32 CHARACTERS. Alembic's `alembic_version.version_num`
#: is `varchar(32)`, and the first name here — "0007_first_completed_and_manifest",
#: 33 characters — ran the DDL and then failed to record itself with
#: `StringDataRightTruncation`. Postgres rolled the transaction back so
#: nothing was half-applied, but the boot would have failed on a deployment
#: mid-upgrade. SQLite has no such limit, so the whole suite passed.
revision = "0007_evidence_time"
down_revision = "0006_tenant_id"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Batch mode so the same migration works on SQLite, which cannot ALTER in
    # place, as well as on PostgreSQL.
    with op.batch_alter_table("sandbox_jobs") as batch:
        batch.add_column(sa.Column("first_completed_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("engine_manifest", sa.JSON(), nullable=True))

    # Backfill: for a job never re-analysed, `completed_at` IS the first
    # completion, and that is the honest value. Guarded so re-running the
    # migration cannot overwrite a real first-completion with a later one.
    op.execute(
        "UPDATE sandbox_jobs "
        "SET first_completed_at = completed_at "
        "WHERE first_completed_at IS NULL AND completed_at IS NOT NULL"
    )


def downgrade() -> None:
    with op.batch_alter_table("sandbox_jobs") as batch:
        batch.drop_column("engine_manifest")
        batch.drop_column("first_completed_at")
