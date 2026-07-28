"""Give every job and every audit event an owning tenant.

The product had no tenant concept: one deployment, one pool of evidence, every
job visible to everyone holding any credential. That is correct for a sovereign
single-organisation install and wrong the moment one deployment serves several
client organisations — which is the whole MSSP channel.

Adding the column now costs one migration against a few hundred rows. Adding it
after a customer's database is full of their evidence means backfilling an owner
onto data whose owner nobody recorded, under load, with the isolation boundary
absent the entire time.

NOT NULL with a server default, not nullable. A nullable owner is an owner
nobody checks, and the single row that slips through as NULL is the one visible
to every tenant at once. Existing rows backfill to "default", which is also
where the analyst session and any bare API key land — so a single-tenant
deployment sees no behavioural change at all.

Revision ID: 0006_tenant_id
Revises: 0005_sample_deleted_at
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006_tenant_id"
down_revision = "0005_sample_deleted_at"
branch_labels = None
depends_on = None

_TABLES = ("sandbox_jobs", "audit_events")


def upgrade() -> None:
    for table in _TABLES:
        # Batch mode so this works on SQLite, which cannot ALTER in place, as
        # well as on PostgreSQL. The server_default is what backfills the
        # existing rows in the same statement, so there is no window in which
        # the column exists and is NULL.
        with op.batch_alter_table(table) as batch:
            batch.add_column(
                sa.Column(
                    "tenant_id",
                    sa.String(length=64),
                    nullable=False,
                    server_default="default",
                )
            )
        op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"])


def downgrade() -> None:
    for table in _TABLES:
        op.drop_index(f"ix_{table}_tenant_id", table_name=table)
        with op.batch_alter_table(table) as batch:
            batch.drop_column("tenant_id")
