"""audit_events: the tamper-evident chain of custody

SECURITY.md previously admitted audit logging was deferred to stdout. A log line
is not evidence: it can be rotated away, and nothing about it proves it was not
edited. This table is the replacement — one row per privileged action, each
hashed over its own content plus the previous row's hash (see app/audit.py).

``prev_hash`` and ``entry_hash`` carry UNIQUE indexes deliberately. Unique
``prev_hash`` means the database itself refuses a fork: two appenders racing
after the same row cannot both commit, so the chain stays linear without a
cross-process lock. Unique ``entry_hash`` means a duplicated row is rejected
rather than quietly doubling an event.

Revision ID: 0004_audit_events
Revises: 0003_impact_rating
Create Date: 2026-07-27
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_audit_events"
down_revision: str | None = "0003_impact_rating"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INDEXES = (
    ("ix_audit_events_occurred_at", ["occurred_at"], False),
    ("ix_audit_events_actor", ["actor"], False),
    ("ix_audit_events_action", ["action"], False),
    ("ix_audit_events_object_id", ["object_id"], False),
    ("ix_audit_events_prev_hash", ["prev_hash"], True),
    ("ix_audit_events_entry_hash", ["entry_hash"], True),
)


def upgrade() -> None:
    # A pre-Alembic database built by the old create_all() from the *current*
    # models already has this table, and db.py dates such a database by the
    # columns on sandbox_jobs alone — it stamps 0003 and then runs this. Creating
    # unconditionally would abort that adoption on "table already exists", i.e.
    # the boot would fail on exactly the installs the stamping exists to rescue.
    if "audit_events" in sa.inspect(op.get_bind()).get_table_names():
        return

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("actor_method", sa.String(length=16), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("object_type", sa.String(length=32), nullable=False),
        sa.Column("object_id", sa.String(length=128), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    for name, columns, unique in _INDEXES:
        op.create_index(name, "audit_events", columns, unique=unique)


def downgrade() -> None:
    # Rolling a release back drops the table with the evidence in it, so an
    # operator downgrading a deployment that has been recording should export
    # /api/audit/export first. Stated here because the alternative — leaving an
    # orphan table behind — makes the next upgrade fail instead.
    for name, _columns, _unique in reversed(_INDEXES):
        op.drop_index(name, table_name="audit_events")
    op.drop_table("audit_events")
