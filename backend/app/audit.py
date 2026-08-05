"""The chain of custody.

An incident-evidence platform has to answer one question to a regulator or an
opposing expert: *who did what to this sample, and when* — completely, and in a
form that a later edit cannot quietly rewrite. A log line on stdout does not
answer it. A row an operator can UPDATE does not answer it either.

So every recorded action is a row in ``audit_events`` whose ``entry_hash`` is a
SHA-256 over its own canonical content **plus the previous row's hash**. That
makes the table a hash chain:

* edit a row and its recomputed hash no longer matches the one stored on it;
* delete a row in the middle and the next row's ``prev_hash`` points at nothing;
* re-order rows and both checks fail.

``verify_chain()`` walks it and names the first broken link. Deleting the *last*
row is the one mutation a self-contained chain cannot see, which is why the
verify endpoint returns ``head_hash``: an operator who anchors that value
somewhere else (a witness system, a printout in the safe, a SIEM) closes the
gap. We state the limit rather than imply we do not have one.

The API over this table is append-only by construction: ``api/audit.py``
declares no PUT, PATCH, POST or DELETE route at all, and nothing here exposes a
way to modify an event once written.

Writing an audit record must never be the reason an analyst's action fails — a
sandbox that refuses uploads because its audit table is full has turned a
bookkeeping problem into an outage. But a silent hole in the chain of custody is
worse than a loud one, so a failed write is logged at ERROR and counted.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, Text, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from . import metrics
from .db import Base, session_scope
from .util import utcnow

logger = logging.getLogger("sandbox.audit")

#: How many events may rest on the chain alone before another signature is
#: written. One per event would double the write cost of every audited action;
#: one per day would leave a day of events unanchored. Fifty bounds the gap to
#: a handful of actions for one Ed25519 signature, which is microseconds.
#:
#: THAT BOUND ONLY HOLDS IF THE TRIGGER CANNOT BE MISSED, and the original
#: `event.id % CHECKPOINT_EVERY == 0` could be. A PostgreSQL sequence burns its
#: value on every rollback, and `record()` rolls back on both its error arms, so
#: allocated ids that never become rows are ordinary here. Measured on the live
#: chain: 1,339 of 15,251 allocated ids do not exist (8.8%), and **34 of the 305
#: multiples of fifty were never written at all** (11.1%) — five of them in
#: consecutive pairs, so three times the intended window was reachable. Largest
#: gap actually observed between two checkpoints: **93 events**.
#:
#: The trigger is now a boundary CROSSING rather than a landing, so a burned id
#: costs nothing: if 14950 never exists, 14951 crosses the same boundary and
#: writes the checkpoint.
CHECKPOINT_EVERY = 50

#: The ``prev_hash`` of the first event. A real hash never collides with it, so
#: "this row claims to be the genesis" is unforgeable in the same way every
#: other link is.
GENESIS_HASH = "0" * 64

#: What replaces a value we refuse to persist. Present in the row so the record
#: still shows that a credential *was* supplied — which is the auditable fact.
REDACTED = "[redacted]"

#: Substrings that make a detail key credential-shaped. The archive-password
#: flow hands the engine a real secret; the audit trail must record that it
#: happened and never what it was.
_SECRET_KEY_MARKERS = (
    "password", "passphrase", "secret", "token", "api_key", "apikey",
    "credential", "authorization", "cookie",
)

#: A failed audit write is a hole in the chain of custody. Counted, not merely
#: logged, so an operator can alert on the first one instead of finding it
#: during discovery. Shares metrics.py's degrade-to-no-op when prometheus_client
#: is absent — audit integrity does not depend on the metrics library.
write_failures_total = metrics._counter(
    "sandbox_audit_write_failures_total",
    "Audit records that could not be persisted",
)


class AuditAction:
    """The recorded vocabulary. Dotted ``subject.verb``, stable across releases:
    a SIEM correlation rule written against these strings is a customer's
    integration, and renaming one silently breaks it."""

    LOGIN_SUCCESS = "login.success"
    LOGIN_FAILURE = "login.failure"
    #: An analyst ending their sessions. The one action that explains why a
    #: token stopped working before its expiry.
    LOGOUT = "login.logout"
    SAMPLE_SUBMITTED = "sample.submitted"
    ARCHIVE_PASSWORD_SUPPLIED = "sample.archive_password_supplied"
    REANALYSIS_REQUESTED = "sample.reanalysis_requested"
    FEEDBACK_RECORDED = "sample.feedback_recorded"
    REPORT_EXPORTED = "report.exported"
    SCORING_WEIGHTS_CHANGED = "config.scoring_weights_changed"
    DYNAMIC_REPORT_INGESTED = "sample.dynamic_report_ingested"
    #: The one action that moves a sample OFF this platform: the raw bytes
    #: handed to the detonation worker. Everything else here records what was
    #: done to the evidence in place.
    SAMPLE_RELEASED_TO_WORKER = "sample.released_to_worker"
    #: Retention deletions. A deletion nobody can prove happened is not one an
    #: auditor accepts, and these two lines are the answer to the erasure clause
    #: in a data-processing agreement.
    SAMPLE_PURGED = "retention.sample_purged"
    REPORT_PURGED = "retention.report_purged"


class AuditOutcome:
    SUCCESS = "success"
    FAILURE = "failure"


class AuditEvent(Base):
    """One immutable link in the chain of custody."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)

    #: Which tenant's action this was. What the audit API filters on, so one
    #: tenant cannot read another's history.
    #:
    #: Deliberately NOT part of `_canonical`, and therefore not covered by
    #: `entry_hash`: that form is frozen, and adding a field to it would make
    #: every event written before tenancy existed fail verification. `record()`
    #: also writes the tenant into `detail`, which IS hashed, so events from here
    #: on carry it inside the chain as well.
    tenant_id: Mapped[str] = mapped_column(
        String(64), nullable=False, default="default", server_default="default", index=True
    )

    #: Who acted. A plain string for the same reason sandbox_jobs.submitted_by is
    #: one: this service owns no users table, it authenticates against configured
    #: credentials and records the subject it authenticated.
    actor: Mapped[str] = mapped_column(String(128), default="", index=True)
    #: How they proved it: session / api_key / worker. A regulator asking whether
    #: a human or a pipeline did this gets the answer without inference.
    actor_method: Mapped[str] = mapped_column(String(16), default="")

    action: Mapped[str] = mapped_column(String(64), default="", index=True)
    object_type: Mapped[str] = mapped_column(String(32), default="")
    object_id: Mapped[str] = mapped_column(String(128), default="", index=True)

    #: ``request.client.host``. Behind a reverse proxy this is the proxy unless
    #: uvicorn was started with --proxy-headers/--forwarded-allow-ips; we do not
    #: read X-Forwarded-For ourselves, because an unvalidated one is attacker
    #: text and a forged source address in an evidence record is worse than none.
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    outcome: Mapped[str] = mapped_column(String(16), default=AuditOutcome.SUCCESS)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)

    #: The previous row's entry_hash. Unique, so the database itself refuses a
    #: fork: two writers racing to append after the same row cannot both win, and
    #: the loser retries onto the new tail instead of branching the chain.
    prev_hash: Mapped[str] = mapped_column(
        String(64), default=GENESIS_HASH, unique=True, index=True
    )
    entry_hash: Mapped[str] = mapped_column(String(64), default="", unique=True, index=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "occurred_at": _iso(self.occurred_at),
            "actor": self.actor,
            "actor_method": self.actor_method,
            "action": self.action,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "source_ip": self.source_ip,
            "outcome": self.outcome,
            "detail": self.detail or {},
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


def _iso(value: datetime) -> str:
    """UTC, naive, microsecond ISO-8601 — identical before and after storage.

    The hash covers the timestamp, so its text form has to survive a round trip
    through the database. SQLite drops tzinfo on the way out, so an aware value
    hashed on write would not re-hash to the same string on verify, and every
    row would read as tampered. Normalising to UTC-without-offset makes the two
    representations one.
    """
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.isoformat(timespec="microseconds")


def _column(value: str | None, limit: int) -> str:
    """Clip a caller-influenced string to its column, and strip what PostgreSQL
    will not take.

    A NUL inside a text parameter makes the driver raise before the statement is
    sent. `record()` never fails the caller's operation -- an audit table must
    not become an outage -- so such a write was logged, counted and dropped, and
    the ACTION went unrecorded. On `/api/auth/login` that is reachable without
    any credential at all: one byte in the username and the failed attempt
    leaves no row in the chain of custody.

    Every column here is caller-influenced somewhere, so the guard lives in one
    place rather than at each call site. `detail` has had `_sanitise` all along;
    the scalars had nothing.
    """
    return (value or "").replace("\x00", "")[:limit]


def _sanitise(detail: dict[str, Any] | None) -> dict[str, Any]:
    """JSON-safe, secret-free detail.

    Two jobs. Credential-shaped keys never keep a value — the audit trail proves
    an archive password was supplied, and holding the password would turn the
    evidence store into the thing worth stealing. Booleans survive, because
    ``{"password_supplied": true}`` is the fact and cannot be the secret.

    Everything else is coerced to a JSON primitive so the stored row and the
    hashed bytes are the same document. A detail value that only stringifies at
    write time would hash differently on the way back in.
    """
    clean: dict[str, Any] = {}
    for raw_key, value in (detail or {}).items():
        key = str(raw_key)
        lowered = key.lower()
        if any(marker in lowered for marker in _SECRET_KEY_MARKERS) and not isinstance(value, bool):
            clean[key] = REDACTED
        elif isinstance(value, bool) or value is None or isinstance(value, (int, float)):
            clean[key] = value
        elif isinstance(value, str):
            # Attacker-controlled in the submission paths (filenames, URLs).
            # Bounded so one submission cannot bloat every export that follows.
            clean[key] = value[:512]
        else:
            clean[key] = str(value)[:512]
    return clean


def _canonical(
    *,
    occurred_at: datetime,
    actor: str,
    actor_method: str,
    action: str,
    object_type: str,
    object_id: str,
    source_ip: str | None,
    outcome: str,
    detail: dict[str, Any],
    prev_hash: str,
) -> bytes:
    """The exact bytes an entry_hash covers.

    Sorted keys and no whitespace: the canonical form must be reproducible from
    the stored row by anyone, including a third party auditing us with nothing
    but the table and this function.
    """
    return json.dumps(
        {
            "occurred_at": _iso(occurred_at),
            "actor": actor,
            "actor_method": actor_method,
            "action": action,
            "object_type": object_type,
            "object_id": object_id,
            "source_ip": source_ip or "",
            "outcome": outcome,
            "detail": detail,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_hash(event: AuditEvent) -> str:
    """Recompute an event's entry_hash from what the row actually holds."""
    return hashlib.sha256(
        _canonical(
            occurred_at=event.occurred_at,
            actor=event.actor or "",
            actor_method=event.actor_method or "",
            action=event.action or "",
            object_type=event.object_type or "",
            object_id=event.object_id or "",
            source_ip=event.source_ip,
            outcome=event.outcome or "",
            detail=event.detail or {},
            prev_hash=event.prev_hash or GENESIS_HASH,
        )
    ).hexdigest()


def _tail(db: Session) -> tuple[int, str]:
    """The id and hash of the newest event, or ``(0, GENESIS_HASH)`` if none.

    It used to return only the hash. The id comes back from the same row for
    free, and the cadence needs it: knowing the PREVIOUS id is what turns
    "did this land on a multiple of fifty" into "did the chain cross one".
    """
    last = db.execute(
        select(AuditEvent.id, AuditEvent.entry_hash)
        .order_by(AuditEvent.id.desc())
        .limit(1)
    ).first()
    if last is None:
        return 0, GENESIS_HASH
    return int(last[0]), (last[1] or GENESIS_HASH)


def _should_checkpoint(prev_id: int, new_id: int) -> bool:
    """Did the chain CROSS a cadence point, rather than land on one?

    `new_id % CHECKPOINT_EVERY == 0` was the shipped test, and it silently
    missed a boundary every time PostgreSQL burned a sequence value on a
    rollback -- which `record()` does on both of its error arms. Measured on the
    live chain: 34 of the 305 multiples of fifty were never written, five of
    them in consecutive pairs, and the largest gap actually observed between two
    checkpoints was 93 events.

    Crossing has no such hole: if 14950 never becomes a row, 14951 still crosses
    the boundary at 14950 and the checkpoint is written.
    """
    if new_id <= 0:
        return False
    return new_id // CHECKPOINT_EVERY > max(prev_id, 0) // CHECKPOINT_EVERY


def record(
    *,
    action: str,
    actor: str,
    actor_method: str,
    object_type: str = "",
    object_id: str = "",
    source_ip: str | None = None,
    outcome: str = AuditOutcome.SUCCESS,
    detail: dict[str, Any] | None = None,
    tenant: str = "",
) -> AuditEvent | None:
    """Append one link to the chain. Returns ``None`` if the write failed.

    Runs in its own session rather than the caller's: an audit record must not
    disappear because the request's transaction rolled back afterwards, and a
    login has no request session at all.

    ``tenant`` lands in two places on purpose. The column is what the audit API
    filters on, so one tenant cannot read another's actions. The copy inside
    ``detail`` is what the hash covers — the canonical form is frozen, and adding
    a field to it would make every event written before today read as tampered,
    which is a worse outcome than a metadata column the chain does not protect.
    """
    clean = _sanitise(detail)
    if tenant:
        # `tenant` is the human-readable copy and has been here from the start.
        # `_tenant` is the RESERVED one the verifier compares against, and it
        # exists because `tenant` is not unambiguous: an audit detail may carry a
        # `tenant` field of its own meaning "the tenant this action was ABOUT",
        # and a verifier that cannot tell the two apart reports tampering on
        # ordinary records. Underscore-prefixed, written only here, never
        # sanitised into by a caller.
        #
        # Stored in the same truncated form as the column, so the comparison is
        # like-for-like: `tenant_id` is `String(64)` and a longer name would
        # otherwise disagree with its own copy for no reason.
        clean = {**clean, "tenant": tenant, "_tenant": _column(tenant, 64)}
    occurred_at = utcnow()
    # Two attempts: a concurrent append makes the unique prev_hash collide, and
    # the correct response is to re-read the tail and chain onto it. A second
    # collision means real contention, not a race we can paper over.
    for attempt in range(2):
        # Opened inside the try: obtaining the session is itself a thing that
        # fails when the database is gone, and that failure must not escape into
        # the analyst's request either.
        db: Session | None = None
        try:
            db = session_scope()
            prev_id, prev_hash = _tail(db)
            event = AuditEvent(
                occurred_at=occurred_at,
                tenant_id=_column(tenant or "default", 64),
                actor=_column(actor, 128),
                actor_method=_column(actor_method, 16),
                action=_column(action, 64),
                object_type=_column(object_type, 32),
                object_id=_column(object_id, 128),
                source_ip=_column(source_ip, 45) or None,
                outcome=outcome,
                detail=clean,
                prev_hash=prev_hash,
            )
            event.entry_hash = compute_hash(event)
            db.add(event)
            # The session does not expire on commit, so the flushed id and every
            # attribute stay readable on the returned, detached event.
            db.commit()
            # Anchor on a cadence rather than on a schedule nobody runs. Inside
            # the try because a checkpoint that fails must not fail the analyst's
            # action either -- `checkpoint` never raises, but obtaining the id
            # after a commit can, and the rule here is that audit bookkeeping is
            # never the reason an upload is refused.
            if event.id and _should_checkpoint(prev_id, event.id):
                checkpoint(db)
            return event
        except IntegrityError:
            db.rollback()
            if attempt == 0:
                continue
            write_failures_total.inc()
            logger.error(
                "AUDIT WRITE FAILED (chain contention) action=%s actor=%s — "
                "this action is NOT in the chain of custody",
                action,
                actor,
            )
            return None
        except Exception:  # noqa: BLE001 — never fail the analyst's operation
            if db is not None:
                db.rollback()
            write_failures_total.inc()
            logger.exception(
                "AUDIT WRITE FAILED action=%s actor=%s — "
                "this action is NOT in the chain of custody",
                action,
                actor,
            )
            return None
        finally:
            if db is not None:
                db.close()
    return None


def verify_chain(db: Session) -> dict[str, Any]:
    """Walk the chain and report the first broken link.

    Returns ``broken_at`` — the id of the earliest row that fails — plus the
    reason, so an investigation starts at a row rather than at a table.
    """
    previous_hash = GENESIS_HASH
    checked = 0
    first_id: int | None = None
    last_id: int | None = None
    #: Rows written before `record()` began copying the tenant into the hashed
    #: detail. For these the column can still be rewritten undetectably, and
    #: saying so is the difference between `ok: true` meaning "verified" and
    #: meaning "verified as far as it goes".
    tenant_unprotected = 0

    for event in db.execute(
        select(AuditEvent).order_by(AuditEvent.id)
    ).scalars():
        if first_id is None:
            first_id = event.id
        if event.prev_hash != previous_hash:
            return _verdict(
                ok=False,
                checked=checked,
                first_id=first_id,
                last_id=last_id,
                head_hash=previous_hash,
                tenant_unprotected=tenant_unprotected,
                broken_at=event.id,
                reason=(
                    "prev_hash does not match the preceding entry — a record was "
                    "deleted, inserted or re-ordered before this one"
                ),
            )
        if compute_hash(event) != event.entry_hash:
            return _verdict(
                ok=False,
                checked=checked,
                first_id=first_id,
                last_id=last_id,
                head_hash=previous_hash,
                tenant_unprotected=tenant_unprotected,
                broken_at=event.id,
                reason="entry_hash does not match this record's content — the record was modified",
            )
        # THE COLUMN IS NOT HASHED; ITS COPY INSIDE `detail` IS.
        #
        # `tenant_id` is deliberately outside the hash so the audit API can index
        # and filter on it, and `append` writes the same value into `detail`,
        # which IS hashed. That design only holds if something compares the two:
        # until it did, `UPDATE audit_events SET tenant_id='other'` moved an
        # event into another tenant's history and `verify_chain` still answered
        # ok, because every hash it checked was untouched. Re-attributing an
        # action is precisely what an audit trail exists to prevent.
        #
        # Events written before the `detail` copy existed carry no `tenant` key
        # and are skipped rather than failed -- a verifier that reports a break
        # on every historical row is one an operator learns to ignore.
        detail = event.detail if isinstance(event.detail, dict) else {}
        hashed_tenant = detail.get("_tenant")
        if hashed_tenant is None:
            tenant_unprotected += 1
        if hashed_tenant is not None and str(hashed_tenant) != str(event.tenant_id or ""):
            return _verdict(
                ok=False,
                checked=checked,
                first_id=first_id,
                last_id=last_id,
                head_hash=previous_hash,
                tenant_unprotected=tenant_unprotected,
                broken_at=event.id,
                reason=(
                    "tenant_id does not match the tenant recorded inside this "
                    "record's hashed detail — the event was re-attributed to a "
                    f"different tenant (column {event.tenant_id!r}, hashed "
                    f"{hashed_tenant!r})"
                ),
            )
        previous_hash = event.entry_hash
        last_id = event.id
        checked += 1

    return _verdict(
        ok=True,
        checked=checked,
        first_id=first_id,
        last_id=last_id,
        head_hash=previous_hash,
        tenant_unprotected=tenant_unprotected,
        broken_at=None,
        reason=None,
    )


def _verdict(
    *,
    ok: bool,
    checked: int,
    first_id: int | None,
    last_id: int | None,
    head_hash: str,
    broken_at: int | None,
    reason: str | None,
    tenant_unprotected: int = 0,
) -> dict[str, Any]:
    return {
        "ok": ok,
        # HOW MANY ROWS THE ATTRIBUTION CHECK COULD NOT COVER.
        #
        # `tenant_id` sits outside the hash so the audit API can index and filter
        # on it, and `record()` writes a `_tenant` copy INSIDE the hashed detail
        # so `verify_chain` can compare the two. That comparison only works on
        # rows written since the copy existed: 14,122 of the 14,145 rows on the
        # live deployment predate it, and for those an `UPDATE` moving an event
        # into another tenant's history is still undetectable.
        #
        # Published beside `ok` rather than left implicit, because `ok: true` on
        # its own reads as "attribution verified" and for those rows it is not.
        # A reader can now tell a fully-covered chain from a mostly-covered one.
        "tenant_unprotected": tenant_unprotected,
        "entries_checked": checked,
        "first_id": first_id,
        "last_id": last_id,
        # Anchor this externally. A chain cannot detect the removal of its own
        # tail; a value recorded elsewhere can.
        "head_hash": head_hash,
        "broken_at": broken_at,
        "reason": reason,
        "verified_at": _iso(utcnow()),
    }


class AuditCheckpoint(Base):
    """A signed statement about the chain at one moment.

    The chain proves it has not been edited *inconsistently*. This proves it has
    not been edited at all, up to the point it covers -- because reproducing a
    checkpoint means producing an Ed25519 signature, and the key for that is on
    the host filesystem rather than in this table.

    Chained to each other through ``prev_checkpoint_hash`` for the same reason
    the events are: otherwise the cheapest attack is to delete the checkpoints.
    """

    __tablename__ = "audit_checkpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)

    #: The event this checkpoint speaks for. 0 with the genesis hash when the
    #: chain is empty -- "nothing had happened yet" is a claim worth signing.
    head_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    #: Rebuilding a shorter chain that ends on the same hash is not possible, but
    #: the count makes a wholesale rebuild fail on arithmetic as well as on
    #: cryptography, and it is the figure a human can check at a glance.
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)

    prev_checkpoint_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    checkpoint_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )

    #: Base64 Ed25519 over ``checkpoint_hash``, and the key that produced it, so
    #: a verifier can tell "signed by a key we no longer trust" from "forged".
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    key_id: Mapped[str] = mapped_column(String(128), nullable=False)

    #: SHA-256 over every event's `(id, tenant_id)` up to `head_id`.
    #:
    #: THE ONE MUTATION THE CHAIN CANNOT SEE. `tenant_id` sits outside
    #: `_canonical` on purpose -- the form is frozen, and adding a field would
    #: make every event written before tenancy fail verification -- so an UPDATE
    #: moving an event into another tenant's history left every hash intact.
    #: `record()` now writes a `_tenant` copy inside the hashed detail, but that
    #: only covers rows written since: 14,122 of 14,145 live rows predate it.
    #:
    #: Backfilling `_tenant` into those rows would change their `detail`, and
    #: therefore their `entry_hash`, and therefore every hash after them -- a
    #: wholesale rewrite of the audit trail, which is the exact act the chain
    #: exists to make impossible. So nothing is rewritten. The attribution is
    #: SIGNED where it stands: a digest over the mapping as it is now, inside a
    #: checkpoint an attacker cannot reproduce without the Ed25519 key.
    #:
    #: Nullable, and omitted from `_checkpoint_canonical` when absent, so every
    #: checkpoint written before this column existed still verifies byte for
    #: byte.
    attribution_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)


def _checkpoint_canonical(
    *,
    created_at: datetime,
    head_id: int,
    head_hash: str,
    event_count: int,
    prev_checkpoint_hash: str,
    attribution_digest: str | None = None,
) -> bytes:
    """The exact bytes a checkpoint_hash covers.

    Same shape and the same reasoning as ``_canonical``: sorted keys, no
    whitespace, reproducible by a third party holding nothing but the table and
    this function.
    """
    body = {
        "created_at": _iso(created_at),
        "head_id": head_id,
        "head_hash": head_hash,
        "event_count": event_count,
        "prev_checkpoint_hash": prev_checkpoint_hash,
    }
    # PRESENT-ONLY, so the form stays frozen for everything already written.
    # Adding a key unconditionally would change the bytes every existing
    # checkpoint hashed, and they would all read as forged -- the same trap
    # `_canonical` carries a note about one level down.
    if attribution_digest:
        body["attribution_digest"] = attribution_digest
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Field and record separators for the attribution digest. Written as escapes,
#: never as literal bytes: `test_the_source_has_no_invisible_control_characters`
#: refuses a control character in the source, and it is right to -- an invisible
#: byte in a hash input is unreviewable.
_UNIT_SEP = chr(0x1F)
_RECORD_SEP = chr(0x1E)


def attribution_digest(db: Session, head_id: int) -> str:
    """SHA-256 over `(id, tenant_id)` for every event up to `head_id`.

    Streamed in id order so the value is reproducible by anyone holding the
    table and this function, and so a table of any size costs one pass and no
    memory. The separator is a byte that cannot occur in either field, which is
    what stops `(1, "a:b")` and `(1, "a"), (":b")` colliding.
    """
    sha = hashlib.sha256()
    rows = db.execute(
        select(AuditEvent.id, AuditEvent.tenant_id)
        .where(AuditEvent.id <= head_id)
        .order_by(AuditEvent.id)
    )
    for event_id, tenant in rows:
        sha.update(f"{int(event_id)}{_UNIT_SEP}{tenant or ''}{_RECORD_SEP}".encode("utf-8"))
    return sha.hexdigest()


def verify_attribution(db: Session) -> dict[str, Any]:
    """Has any event been moved into another tenant since it was last signed?

    Compares the live `(id, tenant_id)` mapping against the newest checkpoint
    that carries a digest. `covered` is the honest half of the answer: events
    written after that checkpoint are not spoken for by it, and saying so is the
    difference between "verified" and "verified as far as it goes".
    """
    row = db.execute(
        select(AuditCheckpoint.head_id, AuditCheckpoint.attribution_digest, AuditCheckpoint.id)
        .where(AuditCheckpoint.attribution_digest.is_not(None))
        .order_by(AuditCheckpoint.id.desc())
        .limit(1)
    ).first()
    if row is None:
        return {
            "checked": False,
            "reason": (
                "no checkpoint carries an attribution digest yet; the next one "
                "written will cover every event up to that point"
            ),
        }
    head_id, signed, checkpoint_id = int(row[0]), row[1], int(row[2])
    live = attribution_digest(db, head_id)
    total = int(db.execute(select(func.count(AuditEvent.id))).scalar_one() or 0)
    covered = int(
        db.execute(
            select(func.count(AuditEvent.id)).where(AuditEvent.id <= head_id)
        ).scalar_one()
        or 0
    )
    return {
        "checked": True,
        "ok": live == signed,
        "covered_events": covered,
        "uncovered_events": max(0, total - covered),
        "checkpoint_id": checkpoint_id,
        "reason": None if live == signed else (
            "an event's tenant_id no longer matches the mapping signed at "
            f"checkpoint {checkpoint_id}: at least one event has been "
            "re-attributed to a different tenant"
        ),
    }


def _checkpoint_tail(db: Session) -> str:
    last = db.execute(
        select(AuditCheckpoint.checkpoint_hash)
        .order_by(AuditCheckpoint.id.desc())
        .limit(1)
    ).scalar_one_or_none()
    return last or GENESIS_HASH


def checkpoint(db: Session, *, settings=None) -> dict[str, Any]:
    """Sign the current head of the chain. Returns what it wrote, or why it did not.

    Never raises. An anchor that fails is a gap in the evidence, but refusing an
    analyst's action because the anchor could not be written turns a bookkeeping
    problem into an outage -- the same rule ``record()`` follows.
    """
    from .engine import attestation

    if settings is None:
        from .config import get_settings

        settings = get_settings()

    private_key, reason = attestation.deployment_key(settings)
    if private_key is None:
        # Said plainly and counted. "No checkpoint" and "checkpoint passing" must
        # never look the same to whoever reads this later.
        logger.warning("audit checkpoint skipped: %s", reason)
        return {"written": False, "reason": reason}

    head = db.execute(
        select(AuditEvent.id, AuditEvent.entry_hash)
        .order_by(AuditEvent.id.desc())
        .limit(1)
    ).first()
    head_id = int(head[0]) if head else 0
    head_hash = head[1] if head else GENESIS_HASH
    count = int(db.execute(select(func.count(AuditEvent.id))).scalar_one() or 0)

    created = utcnow()
    prev = _checkpoint_tail(db)
    attribution = attribution_digest(db, head_id)
    digest = hashlib.sha256(
        _checkpoint_canonical(
            created_at=created,
            head_id=head_id,
            head_hash=head_hash,
            event_count=count,
            prev_checkpoint_hash=prev,
            attribution_digest=attribution,
        )
    ).hexdigest()

    public_key = attestation.public_key_b64(private_key)
    row = AuditCheckpoint(
        created_at=created,
        head_id=head_id,
        head_hash=head_hash,
        event_count=count,
        prev_checkpoint_hash=prev,
        checkpoint_hash=digest,
        attribution_digest=attribution,
        signature=attestation.sign(digest.encode("ascii"), private_key),
        key_id=attestation.key_id(public_key),
    )
    try:
        db.add(row)
        db.commit()
    except IntegrityError:
        # Two appenders raced; the unique index refused the fork. The other one
        # wrote a checkpoint covering at least as much, so there is nothing to do.
        db.rollback()
        return {"written": False, "reason": "a concurrent checkpoint won the race"}
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.error("audit checkpoint failed to write: %s", exc)
        return {"written": False, "reason": f"{type(exc).__name__}"}

    return {
        "written": True,
        "id": row.id,
        "head_id": head_id,
        "head_hash": head_hash,
        "event_count": count,
        "checkpoint_hash": digest,
        "key_id": row.key_id,
        "created_at": _iso(created),
    }


def verify_checkpoints(db: Session, *, settings=None) -> dict[str, Any]:
    """Do the signed anchors still describe this chain?

    Three separate questions, and they fail differently on purpose:

    * the signature -- a re-chained table cannot reproduce it without the key;
    * the checkpoint chain -- deleting an anchor breaks ``prev_checkpoint_hash``;
    * the claim itself -- does the event at ``head_id`` still hash to
      ``head_hash``, and are there still ``event_count`` events at or before it?

    An unsigned deployment reports ``anchored: False`` with the reason. That is
    not a failure of the chain; it is the absence of an anchor, and the two must
    not read the same.
    """
    from .engine import attestation

    if settings is None:
        from .config import get_settings

        settings = get_settings()

    rows = list(db.execute(select(AuditCheckpoint).order_by(AuditCheckpoint.id)).scalars())
    if not rows:
        return {
            "anchored": False,
            "checkpoints": 0,
            "reason": "no checkpoint has been written yet",
        }

    info = attestation.public_key_info(settings)
    public_key = (info or {}).get("public_key") or ""
    if not public_key:
        return {
            "anchored": False,
            "checkpoints": len(rows),
            "reason": (
                "checkpoints exist but this deployment has no public key to check "
                "them against, so they prove nothing here"
            ),
        }

    previous = GENESIS_HASH
    for row in rows:
        if row.prev_checkpoint_hash != previous:
            return _checkpoint_failure(
                rows, row, "a checkpoint was deleted, inserted or re-ordered"
            )

        recomputed = hashlib.sha256(
            _checkpoint_canonical(
                created_at=row.created_at,
                head_id=row.head_id,
                head_hash=row.head_hash,
                event_count=row.event_count,
                prev_checkpoint_hash=row.prev_checkpoint_hash,
                # Passed from the row, so a checkpoint written before the column
                # existed hashes exactly as it did then (the canonical form omits
                # an absent digest) and a newer one covers the attribution too.
                # Reading it back is also what makes the digest tamper-evident:
                # editing the column changes this hash, which breaks the
                # signature over it.
                attribution_digest=row.attribution_digest,
            )
        ).hexdigest()
        if recomputed != row.checkpoint_hash:
            return _checkpoint_failure(rows, row, "a checkpoint's own fields were edited")

        if not attestation.verify(row.checkpoint_hash.encode("ascii"), row.signature, public_key):
            return _checkpoint_failure(
                rows,
                row,
                "a checkpoint's signature does not verify — it was forged, or it "
                "was signed by a different key than this deployment now holds",
            )

        # And the claim. This is the part a re-chained table fails.
        if row.head_id:
            stored = db.execute(
                select(AuditEvent.entry_hash).where(AuditEvent.id == row.head_id)
            ).scalar_one_or_none()
            if stored is None:
                return _checkpoint_failure(
                    rows, row, f"event {row.head_id} named by a checkpoint is gone"
                )
            if stored != row.head_hash:
                return _checkpoint_failure(
                    rows,
                    row,
                    f"event {row.head_id} no longer hashes to what the checkpoint "
                    "signed — the chain was rewritten after this anchor",
                )
        counted = int(
            db.execute(
                select(func.count(AuditEvent.id)).where(AuditEvent.id <= row.head_id)
            ).scalar_one()
            or 0
        )
        if counted != row.event_count:
            return _checkpoint_failure(
                rows,
                row,
                f"{counted} events at or before {row.head_id}, the checkpoint "
                f"signed {row.event_count} — rows were added or removed",
            )
        previous = row.checkpoint_hash

    return {
        "anchored": True,
        "checkpoints": len(rows),
        "latest_head_id": rows[-1].head_id,
        "latest_checkpoint_at": _iso(rows[-1].created_at),
        "key_id": rows[-1].key_id,
        "broken_at": None,
        "reason": None,
        # Stated, not implied: this is what the anchor does and does not cover.
        "covers": (
            "Every event up to the latest checkpoint is anchored to a signature "
            "this database cannot produce. Events after it rely on the chain "
            "alone. An attacker holding the signing key can forge both."
        ),
    }


def _checkpoint_failure(rows, row, reason: str) -> dict[str, Any]:
    return {
        "anchored": False,
        "checkpoints": len(rows),
        "broken_at": row.id,
        "head_id": row.head_id,
        "reason": reason,
    }


def query(
    db: Session,
    *,
    actor: str | None = None,
    action: str | None = None,
    object_type: str | None = None,
    object_id: str | None = None,
    tenant: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[int, list[AuditEvent]]:
    """``(total_matching, page)`` — oldest first, because a chain reads forward.

    ``tenant`` scopes the read. It filters the COUNT as well as the page: a total
    computed over every tenant tells a reader how much traffic the other tenants
    on this deployment are generating, which is a leak that needs no row to be
    returned at all.
    """
    filters = []
    if tenant:
        filters.append(AuditEvent.tenant_id == tenant)
    if actor:
        filters.append(AuditEvent.actor == actor)
    if action:
        filters.append(AuditEvent.action == action)
    if object_type:
        filters.append(AuditEvent.object_type == object_type)
    if object_id:
        filters.append(AuditEvent.object_id == object_id)

    count_query = select(func.count()).select_from(AuditEvent)
    page_query = select(AuditEvent).order_by(AuditEvent.id)
    for condition in filters:
        count_query = count_query.where(condition)
        page_query = page_query.where(condition)

    total = db.execute(count_query).scalar_one()
    rows = db.execute(page_query.limit(limit).offset(offset)).scalars().all()
    return total, list(rows)


# --- SIEM export -------------------------------------------------------------
#: ArcSight CEF severity. A failed action is what a SOC content pack alerts on,
#: so it lands above the "notable but expected" band; a success is recorded, not
#: escalated.
_CEF_SEVERITY = {AuditOutcome.FAILURE: 7, AuditOutcome.SUCCESS: 3}


def _cef_header(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _cef_value(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def to_cef(event: AuditEvent, *, product_version: str) -> str:
    """One CEF line. The format a SOC's ArcSight/Splunk connector already parses.

    The entry hash rides along in a custom string so the SIEM copy can be matched
    back to the row it came from — and so a chain break shows up as a hash the
    SIEM has and the database no longer does.
    """
    severity = _CEF_SEVERITY.get(event.outcome or "", 3)
    header = "|".join(
        _cef_header(part)
        for part in (
            "CEF:0",
            "Cyclowareness",
            "Cyclowareness Sandbox",
            product_version,
            event.action or "",
            (event.action or "").replace(".", " "),
            str(severity),
        )
    )
    occurred = event.occurred_at
    if occurred.tzinfo is None:
        occurred = occurred.replace(tzinfo=timezone.utc)
    extensions = {
        "rt": str(int(occurred.timestamp() * 1000)),
        "suser": event.actor or "",
        "outcome": event.outcome or "",
        "act": event.action or "",
        "cs1Label": "actorMethod",
        "cs1": event.actor_method or "",
        "cs2Label": "objectType",
        "cs2": event.object_type or "",
        "cs3Label": "objectId",
        "cs3": event.object_id or "",
        "cs4Label": "entryHash",
        "cs4": event.entry_hash or "",
        "msg": json.dumps(event.detail or {}, sort_keys=True, separators=(",", ":")),
    }
    if event.source_ip:
        extensions["src"] = event.source_ip
    body = " ".join(f"{key}={_cef_value(value)}" for key, value in extensions.items())
    return f"{header}|{body}"
