"""add cvss, verdict and mitre to sandbox_jobs

The columns f1e2a79 added to the model. Without this revision, booting that code
against a database from the previous release left /api/health returning 200
while every job route raised "no such column: sandbox_jobs.cvss".

The model declares all three NOT NULL, so rows that already exist need a value.
Adding them with a server-side default supplies it in one statement, which is
also the only form SQLite can apply without rewriting the table. The default is
left in place deliberately: it costs nothing, and it means a row written by any
path that bypasses the ORM still satisfies the constraint.

Revision ID: 0002_cvss_verdict_mitre
Revises: 0001_baseline
Create Date: 2026-07-27
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_cvss_verdict_mitre"
down_revision: str | None = "0001_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # batch_alter_table so the same revision runs on SQLite (which cannot ALTER
    # in place and needs the table rewritten) and on PostgreSQL (where batch
    # mode renders a plain ALTER TABLE).
    with op.batch_alter_table("sandbox_jobs") as batch:
        batch.add_column(
            sa.Column("cvss", sa.JSON(), nullable=False, server_default=sa.text("'{}'"))
        )
        batch.add_column(
            sa.Column("verdict", sa.JSON(), nullable=False, server_default=sa.text("'{}'"))
        )
        batch.add_column(
            sa.Column("mitre", sa.JSON(), nullable=False, server_default=sa.text("'[]'"))
        )


def downgrade() -> None:
    # A real rollback path, not a stub: an operator who has to revert to the
    # previous release must be able to get the database back to its schema.
    # The three columns' contents are derived from `analysis`, so dropping them
    # loses no evidence — re-running the analysis reproduces them.
    with op.batch_alter_table("sandbox_jobs") as batch:
        batch.drop_column("mitre")
        batch.drop_column("verdict")
        batch.drop_column("cvss")
