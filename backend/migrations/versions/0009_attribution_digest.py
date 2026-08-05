"""audit_checkpoints.attribution_digest: sign which tenant owns which event

Revision ID: 0009_attribution_digest
Revises: 0008_audit_anchor
Create Date: 2026-08-04

`tenant_id` is deliberately outside `audit._canonical`, and therefore outside
`entry_hash`: that form is frozen, and adding a field to it would make every
event written before tenancy existed read as tampered. The consequence is that
one `UPDATE audit_events SET tenant_id=...` moves an event into another tenant's
history while every hash in the chain stays intact and `verify_chain` answers
`ok: true`.

`record()` now writes a `_tenant` copy inside the hashed detail, which closes it
for new rows. It cannot close it for old ones: 14,122 of the 14,145 rows on the
live deployment predate that change, and backfilling `_tenant` into them would
change their `detail`, their `entry_hash`, and every hash after them -- a
wholesale rewrite of the audit trail, which is the precise act the chain exists
to make impossible.

So nothing is rewritten. The attribution is signed where it stands: a SHA-256
over every `(id, tenant_id)` pair, stored in the next checkpoint and covered by
its Ed25519 signature. Reproducing it after a change means producing that
signature, and the key is on the host filesystem rather than in this table.

Nullable on purpose. `_checkpoint_canonical` omits the field when it is absent,
so every checkpoint written before this migration hashes to exactly the same
value it always did and keeps verifying.
"""
from alembic import op
import sqlalchemy as sa

revision = "0009_attribution_digest"
down_revision = "0008_audit_anchor"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "audit_checkpoints",
        sa.Column("attribution_digest", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("audit_checkpoints", "attribution_digest")
