"""The worker queue must drain a backlog, not just serve the newest arrivals.

Found on a real 107-sample run. After about 45 detonations the worker started
receiving `queue: 0 job(s)` and the whole pipeline went idle for ninety minutes,
while the database held **71 completed jobs with `dynamic.ran = false`**.

Two causes, both in one query:

* `LIMIT` was applied in SQL and `_needs_dynamic` in Python, so the endpoint
  fetched N rows, threw away the ones already detonated, and returned the
  remainder. Once the newest N had all run it returned an empty list forever.
* Ordering was newest-first, which starves a backlog under sustained submission:
  fresh jobs keep arriving at the head and anything that missed its turn is never
  offered again.

Nothing errored. The sandbox simply stopped working, which is why it needs a
test rather than a fix.
"""
from __future__ import annotations

import pytest

from tests.test_api import WORKER_TOKEN, _poll_until_done, _submit


def _queue(client, limit: int = 20) -> list[dict]:
    r = client.get(
        f"/api/dynamic/queue?limit={limit}", headers={"X-Worker-Token": WORKER_TOKEN}
    )
    assert r.status_code == 200, r.text
    return r.json()


def _report(client, public_id: str) -> None:
    """Mark a job detonated, the way a worker does."""
    r = client.post(
        f"/api/dynamic/report/{public_id}",
        json={
            "engine": "capev2", "worker": "test", "ran": True,
            "unavailable_reason": None,
            "signals": [{"id": "capev2.x", "title": "x", "severity": "low",
                         "detail": "", "evidence": {}}],
            "facts": {}, "iocs": {}, "duration_ms": 1, "timeline": [],
        },
        headers={"X-Worker-Token": WORKER_TOKEN},
    )
    assert r.status_code == 200, r.text


@pytest.fixture()
def backlog(client, auth):
    """More detonatable jobs than a single queue page returns."""
    ids = []
    for n in range(7):
        pid = _submit(client, auth, f"backlog_{n}.exe", b"MZ" + bytes([n]) * 4096)
        _poll_until_done(client, auth, pid)
        ids.append(pid)
    return ids


def test_the_queue_keeps_serving_until_the_backlog_is_empty(client, backlog) -> None:
    """Ask for a small page, detonate it, ask again — until nothing is left.

    With the old query this stopped returning work while jobs remained.
    """
    served: set[str] = set()
    for _ in range(40):
        batch = _queue(client, limit=100)
        if not batch:
            break
        for item in batch:
            served.add(item["public_id"])
            _report(client, item["public_id"])
    assert served >= set(backlog), (
        f"queue went empty with {len(set(backlog) - served)} job(s) still undetonated"
    )


def test_a_small_page_is_still_a_full_page(client, backlog) -> None:
    """`limit=2` must return two jobs while two are waiting, not two candidates
    minus however many of them had already run."""
    assert len(_queue(client, limit=2)) == 2


def test_the_oldest_waiting_job_is_offered_first(client, db, backlog) -> None:
    """Newest-first starves a backlog: fresh arrivals keep taking the head.

    This used to assert on the order of THIS test's own jobs within the page,
    which was the right instinct about the shared database and the wrong
    mechanism. Its own jobs are the newest, the queue is offered oldest-first,
    and the endpoint caps a page at 100 rows — so once other tests had left more
    than a hundred jobs waiting, none of this test's jobs was on the page at all
    and the assertion compared `[]` against seven ids. It failed in two runs out
    of six, on nothing but the order the suite happened to run in.

    So the property is asserted where it actually lives: every job the queue
    offers, in the order it offers them, must be non-decreasing in `created_at`.
    That is what "oldest first" means, it is true of any page, and it no longer
    depends on how much work the rest of the suite left behind.
    """
    from sqlalchemy import select

    from app.engine.models import SandboxJob

    order = [j["public_id"] for j in _queue(client, limit=100)]
    assert order, "the fixture just created seven detonatable jobs"

    created = {
        job.public_id: job.created_at
        for job in db.execute(
            select(SandboxJob).where(SandboxJob.public_id.in_(order))
        ).scalars().all()
    }
    stamps = [created[public_id] for public_id in order]
    assert stamps == sorted(stamps), "the queue is not offered oldest-first"

    # And when this test's own jobs ARE on the page, they keep their submission
    # order among themselves — the original assertion, minus the assumption that
    # all seven are visible.
    mine = [p for p in order if p in set(backlog)]
    assert mine == [p for p in backlog if p in set(order)], (
        "own jobs were not offered oldest-first"
    )


def test_a_detonated_job_is_not_offered_again(client, backlog) -> None:
    first = _queue(client, limit=1)[0]["public_id"]
    _report(client, first)
    assert first not in {j["public_id"] for j in _queue(client, limit=20)}


def test_a_job_leaves_the_queue_once_it_has_run(client, backlog) -> None:
    """Scoped to this test's jobs: the suite shares one database, so an empty
    queue is not something a single test can assert."""
    for pid in backlog:
        _report(client, pid)
    remaining = {j["public_id"] for j in _queue(client, limit=100)}
    assert not (set(backlog) & remaining)
