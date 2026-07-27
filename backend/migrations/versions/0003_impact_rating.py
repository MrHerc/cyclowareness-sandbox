"""rename sandbox_jobs.cvss to sandbox_jobs.impact

The column held a number we had no right to call CVSS: FIRST scopes CVSS to
vulnerabilities, and a malware sample is not one. The rating is now the
Cyclowareness Impact Rating (see app/engine/impact.py) and the column follows it.

A rename rather than add-column-then-backfill-then-drop, because a rename moves
the existing values with the row. That is what "existing rows still render" means
in practice: a job rated by the previous release keeps its vector and its score,
and no data migration can fail halfway. The vectors inside those old rows still
read ``CVSS:3.1/...`` — they are what the engine wrote at the time and rewriting
them would be falsifying the record; the read paths render whatever notation the
row carries, and re-analysing a sample re-rates it as CIR.

Revision ID: 0003_impact_rating
Revises: 0002_cvss_verdict_mitre
Create Date: 2026-07-27
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_impact_rating"
down_revision: str | None = "0002_cvss_verdict_mitre"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: 0002 added the column with this server-side default and left it in place so a
#: row written outside the ORM still satisfies NOT NULL. Restated on both sides of
#: the rename because SQLite runs this in batch mode, which rebuilds the table
#: from what it is told rather than from what was there.
_JSON_OBJECT_DEFAULT = sa.text("'{}'")


def upgrade() -> None:
    with op.batch_alter_table("sandbox_jobs") as batch:
        batch.alter_column(
            "cvss",
            new_column_name="impact",
            existing_type=sa.JSON(),
            existing_nullable=False,
            existing_server_default=_JSON_OBJECT_DEFAULT,
        )


def downgrade() -> None:
    with op.batch_alter_table("sandbox_jobs") as batch:
        batch.alter_column(
            "impact",
            new_column_name="cvss",
            existing_type=sa.JSON(),
            existing_nullable=False,
            existing_server_default=_JSON_OBJECT_DEFAULT,
        )
