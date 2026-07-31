"""audit_checkpoints: the anchor the chain could not provide for itself

`app/audit.py` was honest about its own limit and the docstring still says it:
"Deleting the *last* row is the one mutation a self-contained chain cannot see,
which is why the verify endpoint returns ``head_hash``: an operator who anchors
that value somewhere else ... closes the gap."

Two problems with leaving it there. The obvious one is that nobody anchors it.
The larger one is that truncation was never the worst case: anyone who can
UPDATE the table can edit a row, recompute every following `entry_hash`, and
`verify_chain` returns ok. The chain proves internal consistency, and internal
consistency is exactly what an attacker with write access can restore.

A checkpoint is a signed statement about the chain at a moment: "at event
``head_id`` the head hash was ``head_hash`` and there were ``event_count``
events". It is signed with the deployment's Ed25519 key, which lives on the host
filesystem and not in the database. So re-chaining now needs the key as well as
the table, and the two are not compromised by the same thing.

Checkpoints are themselves chained through ``prev_checkpoint_hash``, so removing
one is as visible as removing an event. ``checkpoint_hash`` and
``prev_checkpoint_hash`` carry UNIQUE indexes for the same reason
``audit_events`` does: the database refuses a fork rather than relying on a
cross-process lock.

Nothing here weakens the existing guarantee, and nothing depends on a third
party. It does NOT defend against an attacker who also holds the signing key --
no scheme rooted in one key does -- and `verify_chain` says so in its reason
string rather than implying otherwise.

Revision ID: 0008_audit_anchor
Revises: 0007_evidence_time
Create Date: 2026-07-31
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_audit_anchor"
down_revision: str | None = "0007_evidence_time"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INDEXES = (
    ("ix_audit_checkpoints_created_at", ["created_at"], False),
    ("ix_audit_checkpoints_head_id", ["head_id"], False),
    ("ix_audit_checkpoints_prev_checkpoint_hash", ["prev_checkpoint_hash"], True),
    ("ix_audit_checkpoints_checkpoint_hash", ["checkpoint_hash"], True),
)


def upgrade() -> None:
    # Same guard as 0004: a pre-Alembic database built by the old create_all()
    # from the current models already has this table, and db.py dates such a
    # database by the columns on sandbox_jobs alone. Creating unconditionally
    # would abort the adoption these stamps exist to rescue.
    if "audit_checkpoints" in sa.inspect(op.get_bind()).get_table_names():
        return

    op.create_table(
        "audit_checkpoints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        # The event this checkpoint speaks for. NULL head_id is not allowed:
        # a checkpoint over an empty chain still names id 0 and the genesis hash,
        # so "no events yet" is itself a signed statement.
        sa.Column("head_id", sa.Integer(), nullable=False),
        sa.Column("head_hash", sa.String(64), nullable=False),
        # How many events existed. Truncation that preserves the head hash is
        # impossible, but a rebuild that fakes both is caught by the count.
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("prev_checkpoint_hash", sa.String(64), nullable=False),
        sa.Column("checkpoint_hash", sa.String(64), nullable=False),
        # Base64 Ed25519 over checkpoint_hash, and the key that made it, so a
        # verifier can tell "signed by a key we no longer trust" from "forged".
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("key_id", sa.String(128), nullable=False),
    )
    for name, columns, unique in _INDEXES:
        op.create_index(name, "audit_checkpoints", columns, unique=unique)


def downgrade() -> None:
    for name, _, _ in _INDEXES:
        op.drop_index(name, table_name="audit_checkpoints")
    op.drop_table("audit_checkpoints")
