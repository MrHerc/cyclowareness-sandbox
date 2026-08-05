"""`verify_chain` returned ok for a log that had been rewritten.

The module was honest about one limit -- "deleting the *last* row is the one
mutation a self-contained chain cannot see" -- and understated the real one. Any
principal who can UPDATE the table can edit a row, recompute every following
`entry_hash`, and verification passes. Internal consistency is precisely what an
attacker with write access can restore, so proving it proves very little.

A checkpoint is a signed statement about the chain at a moment: "at event N the
head hash was H and there were C events", signed with the deployment's Ed25519
key. The key lives on the host filesystem, not in the database, so rewriting the
chain now needs two different compromises instead of one.

The checkpoints are chained to each other as well, because otherwise the cheapest
attack is to delete the anchors and leave a chain that verifies.

What it does NOT do, asserted here rather than left to a reader's optimism: it
does not defend against someone holding the signing key, and it does not anchor
events written since the last checkpoint. `verify_checkpoints` says both.

NOTE for whoever edits this file: **the `db` fixture does not reset between
tests.** Every assertion below is on rows this test created, or on a delta it
measured itself. An absolute count here passes alone and fails in a full run.
"""
from __future__ import annotations

import base64
import hashlib

import pytest
from sqlalchemy import func, select

from app import audit
from app.config import Settings

SEED = base64.b64encode(bytes(range(32))).decode("ascii")


@pytest.fixture()
def signed() -> Settings:
    return Settings(signing_key=SEED)


@pytest.fixture()
def chain(tmp_path):
    """A chain of its own, for the tests that deliberately damage one.

    The shared `db` fixture does not reset between tests, and these tests rewrite
    and delete rows on purpose. Run against the shared session they detect each
    other's damage first and assert on the wrong reason string -- which is the
    anchor working correctly and the test lying about why.

    Two tables and a session. `audit.record` writes through `session_scope`, so
    the module-level engine is repointed for the duration.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app import db as db_module

    engine = create_engine(f"sqlite:///{tmp_path / 'chain.db'}", future=True)
    audit.AuditEvent.__table__.create(engine)
    audit.AuditCheckpoint.__table__.create(engine)
    maker = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    original_scope = db_module.session_scope
    original_audit_scope = audit.session_scope
    db_module.session_scope = maker
    audit.session_scope = maker
    session = maker()
    try:
        yield session
    finally:
        session.close()
        db_module.session_scope = original_scope
        audit.session_scope = original_audit_scope
        engine.dispose()


def _events(db, n: int, tag: str) -> list[int]:
    """Append `n` events and return their ids, so a test can find its own."""
    ids = []
    for i in range(n):
        event = audit.record(
            actor="analyst",
            actor_method="session",
            action="job.viewed",
            object_type="job",
            object_id=f"{tag}-{i}",
            outcome="success",
            detail={"tag": tag, "i": i},
            tenant="default",
        )
        assert event is not None
        ids.append(event.id)
    return ids


def _rechain_from(db, first_id: int) -> None:
    """Edit the event at `first_id` and repair every hash after it, as an
    attacker with UPDATE would. Starts from a row this test owns."""
    rows = list(
        db.execute(
            select(audit.AuditEvent).where(audit.AuditEvent.id >= first_id)
            .order_by(audit.AuditEvent.id)
        ).scalars()
    )
    assert rows
    rows[0].detail = {**(rows[0].detail or {}), "tampered": True}
    previous = rows[0].prev_hash
    for row in rows:
        row.prev_hash = previous
        row.entry_hash = audit.compute_hash(row)
        previous = row.entry_hash
    db.commit()


def _count(db) -> int:
    return int(db.execute(select(func.count(audit.AuditEvent.id))).scalar_one() or 0)


# --- the premise -------------------------------------------------------------

def test_a_rechained_log_still_passes_the_chain_check(chain) -> None:
    """Stated as a test because it is the reason the anchor exists."""
    ids = _events(chain, 4, "premise")
    assert audit.verify_chain(chain)["ok"] is True
    _rechain_from(chain, ids[1])
    assert audit.verify_chain(chain)["ok"] is True, (
        "if this ever fails the chain got stronger and this file can be revisited"
    )


# --- what the anchor adds ----------------------------------------------------

def test_a_checkpoint_is_written_and_verifies(db, signed) -> None:
    _events(db, 3, "written")
    expected = _count(db)

    result = audit.checkpoint(db, settings=signed)
    assert result["written"] is True, result
    assert result["event_count"] == expected

    verified = audit.verify_checkpoints(db, settings=signed)
    assert verified["anchored"] is True, verified
    assert verified["broken_at"] is None


def test_the_rechained_log_is_caught_by_the_anchor(chain, signed) -> None:
    """The finding this whole file is about."""
    ids = _events(chain, 5, "caught")
    assert audit.checkpoint(chain, settings=signed)["written"] is True
    _rechain_from(chain, ids[1])

    assert audit.verify_chain(chain)["ok"] is True          # still internally consistent
    result = audit.verify_checkpoints(chain, settings=signed)
    assert result["anchored"] is False, result
    assert result["broken_at"] is not None


def test_deleting_the_tail_is_caught(chain, signed) -> None:
    """The limit the module already admitted to."""
    ids = _events(chain, 4, "tail")
    assert audit.checkpoint(chain, settings=signed)["written"] is True

    row = chain.execute(
        select(audit.AuditEvent).where(audit.AuditEvent.id == ids[-1])
    ).scalars().one()
    chain.delete(row)
    chain.commit()

    result = audit.verify_checkpoints(chain, settings=signed)
    assert result["anchored"] is False, result


def test_deleting_a_checkpoint_is_caught(chain, signed) -> None:
    """Otherwise the cheapest attack is to remove the anchors."""
    _events(chain, 2, "cp-a")
    assert audit.checkpoint(chain, settings=signed)["written"] is True
    _events(chain, 2, "cp-b")
    first = audit.checkpoint(chain, settings=signed)
    assert first["written"] is True
    _events(chain, 2, "cp-c")
    assert audit.checkpoint(chain, settings=signed)["written"] is True

    middle = chain.execute(
        select(audit.AuditCheckpoint).where(audit.AuditCheckpoint.id == first["id"])
    ).scalars().one()
    chain.delete(middle)
    chain.commit()

    result = audit.verify_checkpoints(chain, settings=signed)
    assert result["anchored"] is False, result
    assert "deleted" in result["reason"] or "re-ordered" in result["reason"], result["reason"]


def test_editing_a_checkpoint_is_caught(chain, signed) -> None:
    _events(chain, 3, "edit")
    written = audit.checkpoint(chain, settings=signed)
    assert written["written"] is True

    row = chain.execute(
        select(audit.AuditCheckpoint).where(audit.AuditCheckpoint.id == written["id"])
    ).scalars().one()
    row.event_count = row.event_count + 500
    chain.commit()

    result = audit.verify_checkpoints(chain, settings=signed)
    assert result["anchored"] is False, result


def test_a_forged_checkpoint_cannot_be_signed(chain, signed) -> None:
    """The attacker repairs the checkpoint hash but cannot produce the signature."""
    ids = _events(chain, 4, "forge")
    written = audit.checkpoint(chain, settings=signed)
    assert written["written"] is True
    _rechain_from(chain, ids[1])

    row = chain.execute(
        select(audit.AuditCheckpoint).where(audit.AuditCheckpoint.id == written["id"])
    ).scalars().one()
    head = chain.execute(
        select(audit.AuditEvent).where(audit.AuditEvent.id == row.head_id)
    ).scalars().one()
    row.head_hash = head.entry_hash
    row.checkpoint_hash = hashlib.sha256(
        audit._checkpoint_canonical(
            created_at=row.created_at,
            head_id=row.head_id,
            head_hash=row.head_hash,
            event_count=row.event_count,
            prev_checkpoint_hash=row.prev_checkpoint_hash,
            # The attacker here has to be as capable as a real one: they read the
            # code, so they repair the hash over ALL of the canonical form. With
            # `attribution_digest` omitted the hash check caught them first and
            # the test stopped exercising the thing it is named after -- the
            # signature is what they cannot produce, and that has to be the step
            # that refuses them.
            attribution_digest=row.attribution_digest,
        )
    ).hexdigest()
    chain.commit()

    result = audit.verify_checkpoints(chain, settings=signed)
    assert result["anchored"] is False, result
    assert "signature" in result["reason"], result["reason"]


# --- honesty when there is no key -------------------------------------------

def test_an_unsigned_deployment_says_so_rather_than_passing(db) -> None:
    """"Not anchored" and "anchored and fine" must never read the same."""
    unsigned = Settings(signing_key="")
    _events(db, 2, "unsigned")

    written = audit.checkpoint(db, settings=unsigned)
    assert written["written"] is False
    assert written["reason"]


def test_checkpoints_without_a_key_to_check_them_prove_nothing(db, signed) -> None:
    """A deployment that lost its key must not read as verified."""
    _events(db, 2, "keyless")
    assert audit.checkpoint(db, settings=signed)["written"] is True

    result = audit.verify_checkpoints(db, settings=Settings(signing_key=""))
    assert result["anchored"] is False, result
    assert "no public key" in result["reason"], result["reason"]


def test_the_anchor_states_what_it_does_not_cover(db, signed) -> None:
    """A claim about evidence has to carry its own limits."""
    _events(db, 2, "covers")
    assert audit.checkpoint(db, settings=signed)["written"] is True
    covers = audit.verify_checkpoints(db, settings=signed)["covers"]
    assert "signing key" in covers
    assert "after it" in covers


def test_events_after_the_last_checkpoint_do_not_break_it(db, signed) -> None:
    """Ordinary operation: the chain keeps growing between anchors."""
    _events(db, 2, "growing-a")
    assert audit.checkpoint(db, settings=signed)["written"] is True
    _events(db, 7, "growing-b")
    assert audit.verify_checkpoints(db, settings=signed)["anchored"] is True


# --- the cadence -------------------------------------------------------------

def test_a_checkpoint_appears_without_anyone_asking(db, signed, monkeypatch) -> None:
    """An anchor nobody writes is the same as no anchor at all."""
    import app.config

    monkeypatch.setattr(audit, "CHECKPOINT_EVERY", 3)
    monkeypatch.setattr(app.config, "get_settings", lambda: signed)

    before = int(
        db.execute(select(func.count(audit.AuditCheckpoint.id))).scalar_one() or 0
    )
    _events(db, 9, "cadence")
    after = int(
        db.execute(select(func.count(audit.AuditCheckpoint.id))).scalar_one() or 0
    )
    assert after > before, "record() should have anchored on the cadence"


# --- what the ENDPOINT says, which is what an auditor actually reads ---------
#
# `verify_checkpoints` was honest all along: both "not anchored" branches return
# `{"anchored": False, "reason": ...}`. The endpoint then asked only about
# `broken_at` — a key NEITHER of those branches sets — so `.get()` yielded None,
# the condition was false, and `/api/audit/verify` answered `ok: true` for a
# chain with no anchor whatsoever. Three lines above it sits a comment saying
# internal consistency is exactly what an attacker with UPDATE can restore, and
# `docs/api.md` told auditors this endpoint "answers the only question that
# matters about an audit log".
#
# `ok` is NOT flipped: "not anchored" and "chain broken" must not read the same,
# which the two tests above hold. The absence is surfaced beside `ok` instead.

def test_the_endpoint_reports_an_unanchored_chain_beside_ok(client, auth) -> None:
    """`ok: true` alone must not be readable as "this log is vouched for"."""
    response = client.get("/api/audit/verify", headers=auth)
    assert response.status_code == 200, response.text
    body = response.json()

    assert "anchored" in body, (
        "an auditor reading the top level cannot see whether anything signed "
        "vouches for this chain: " + ", ".join(sorted(body))
    )
    assert isinstance(body["anchored"], bool)
    assert body["anchored"] == bool(body["anchor"].get("anchored")), body

    if not body["anchored"]:
        assert body.get("anchor_reason"), "an unanchored chain must say why"
    else:
        # The claim carries its own limits, at the level it is read.
        assert body["anchor"].get("covers")


def test_a_chain_with_no_checkpoints_is_not_reported_as_vouched_for(db) -> None:
    """The branch the endpoint could not see. No checkpoint has been written,
    so there is nothing signed to check — and that is not `broken_at`."""
    result = audit.verify_checkpoints(db)
    assert result["anchored"] is False
    assert "broken_at" not in result, (
        "if this branch ever grows a broken_at, the endpoint's older condition "
        "would start reading 'unsigned' as 'tampered'"
    )
    assert result["reason"]


# --- the cadence has to be a crossing, not a landing -------------------------
#
# `event.id % CHECKPOINT_EVERY == 0` assumes every multiple of fifty becomes a
# row. A PostgreSQL sequence burns its value on rollback and `record()` rolls
# back on both of its error arms, so it does not. Measured on the live chain:
# 1,339 of 15,251 allocated ids do not exist, **34 of the 305 multiples of fifty
# were never written**, five of those in consecutive pairs, and the largest gap
# actually observed between two checkpoints was **93 events** — against a
# docstring promising fifty bounds it "to a handful of actions".

def test_a_burned_sequence_value_no_longer_skips_an_anchor() -> None:
    """The exact live failure: 14950 was allocated to a rolled-back insert and
    never became a row, so nothing anchored that boundary."""
    assert audit._should_checkpoint(14949, 14951) is True


def test_it_anchors_once_per_block_not_once_per_event() -> None:
    crossings = sum(audit._should_checkpoint(i - 1, i) for i in range(101, 201))
    assert crossings == 2, "one crossing at 150 and one at 200, not %d" % crossings


def test_two_consecutive_missing_boundaries_still_anchor_once() -> None:
    """8900 and 8950 were both missing on the live chain. The first event past
    them closes the window rather than waiting for 9000."""
    assert audit._should_checkpoint(8899, 8951) is True


def test_landing_exactly_on_a_boundary_still_anchors() -> None:
    """The behaviour that already worked must keep working."""
    assert audit._should_checkpoint(14949, 14950) is True


def test_an_ordinary_event_does_not_anchor() -> None:
    assert audit._should_checkpoint(14951, 14952) is False


def test_the_first_event_of_all_does_not_anchor_on_a_bare_id() -> None:
    """`prev_id` is 0 on an empty chain; event 1 is not a cadence point."""
    assert audit._should_checkpoint(0, 1) is False
    assert audit._should_checkpoint(0, audit.CHECKPOINT_EVERY) is True


def test_the_tail_returns_the_id_as_well_as_the_hash(db) -> None:
    """The whole reason the crossing test costs no extra query."""
    assert audit._tail(db) == (0, audit.GENESIS_HASH) or isinstance(audit._tail(db)[0], int)
    _events(db, 1, "tail")
    tail_id, tail_hash = audit._tail(db)
    assert tail_id > 0 and len(tail_hash) == 64


def test_the_modulo_form_is_gone() -> None:
    """A guard on the shape, because the old form reads perfectly reasonable."""
    import pathlib

    source = pathlib.Path(audit.__file__).read_text(encoding="utf-8")
    body = source[source.index("def record("):source.index("def checkpoint(")]
    assert "% CHECKPOINT_EVERY == 0" not in body, (
        "the cadence is back to landing on a multiple, which the sequence skips"
    )
    assert "_should_checkpoint" in body
