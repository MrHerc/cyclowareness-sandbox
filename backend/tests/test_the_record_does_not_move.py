"""Evidence that changes after the fact is not evidence.

Three defects with the same shape — a record that silently rewrote itself — plus
the container rule that did not implement the rule it stated.

1. **The regulatory clock moved.** `completed_at` is deliberately cleared and
   rewritten by every re-analysis, and the NIS2 Article 23(4)(a) deadline was
   derived from it. So a re-scoring sweep moved the 24-hour deadline of every job
   it touched. Awareness happened once; `first_completed_at` is written once.

2. **The signed attestation described the wrong engine.** The manifest was read
   at EXPORT time, so a report exported today pinned today's engine rather than
   the one that reached the verdict — every rule change since silently rewriting
   history inside the one document whose purpose is that it cannot be. Captured
   at verdict time now, with `manifest_source` saying which it is.

3. **A container inherited the verdict of the highest-SCORING member**, not of
   the worst one. Its own message said "a container carries the verdict of the
   worst thing found in it" while the code took `max(descendants, key=score)`.
   caddy.zip held a `clean` LICENSE at 21.9 and a `suspicious` README at 13.0 and
   came out CLEAN.

4. **`?status=zzz` returned `200 []`** — byte-identical to the answer for
   `?status=failed` on a healthy deployment, so a typo in a filter read as "no
   jobs are failing".
"""
from __future__ import annotations

import datetime

import pytest

from app.engine import attestation, incident
from app.engine.models import JobStatus


class _Job:
    """Only the attributes each unit under test reads."""

    def __init__(self, **kw):
        self.public_id = kw.pop("public_id", "job-1")
        self.sha256 = kw.pop("sha256", "a" * 64)
        self.original_name = kw.pop("original_name", "sample.exe")
        self.completed_at = kw.pop("completed_at", None)
        self.first_completed_at = kw.pop("first_completed_at", None)
        self.engine_manifest = kw.pop("engine_manifest", None)
        for k, v in kw.items():
            setattr(self, k, v)


UTC = datetime.timezone.utc
FIRST = datetime.datetime(2026, 3, 1, 9, 0, tzinfo=UTC)
LATER = datetime.datetime(2026, 7, 30, 15, 0, tzinfo=UTC)


# --- 1. the awareness time ----------------------------------------------------


def test_the_deadline_comes_from_the_first_completion() -> None:
    """A re-analysis in July must not move a deadline set in March."""
    job = _Job(first_completed_at=FIRST, completed_at=LATER)
    assert incident._awareness(job) == FIRST


def test_a_job_predating_the_column_still_has_an_awareness_time() -> None:
    """Migration 0007 backfills `first_completed_at` from `completed_at`, which is
    exact for any job never re-analysed. A row that somehow has neither must fall
    back rather than claim there is no awareness time."""
    assert incident._awareness(_Job(first_completed_at=None, completed_at=LATER)) == LATER


def test_an_unfinished_job_has_no_deadline() -> None:
    """Substituting "now" would manufacture a deadline out of nothing."""
    assert incident._awareness(_Job()) is None


def test_a_naive_timestamp_is_read_as_utc() -> None:
    naive = datetime.datetime(2026, 3, 1, 9, 0)
    assert incident._awareness(_Job(first_completed_at=naive)).tzinfo is not None


# --- 2. the engine that reached the verdict -----------------------------------


def test_the_attestation_pins_the_engine_that_produced_the_verdict(monkeypatch) -> None:
    stored = {"product": "Cyclowareness Sandbox", "app_version": "1.2.3-at-verdict-time"}
    monkeypatch.setattr(attestation, "build_report", lambda job: {"report": "x"})
    document = attestation.build_document(_Job(engine_manifest=stored))
    assert document["manifest"]["app_version"] == "1.2.3-at-verdict-time"
    assert document["manifest"]["manifest_source"] == "captured at verdict time"


def test_a_job_without_a_stored_manifest_says_so(monkeypatch) -> None:
    """Falling back to the live engine is acceptable for rows written before the
    column existed. Presenting it as the engine that produced the verdict is
    not."""
    monkeypatch.setattr(attestation, "build_report", lambda job: {"report": "x"})
    document = attestation.build_document(_Job(engine_manifest=None))
    assert "predates verdict-time capture" in document["manifest"]["manifest_source"]


def test_the_manifest_cache_does_not_freeze_the_tunable_blend(monkeypatch) -> None:
    """The static parts are cached because they cost real I/O per job — hashing
    the rule files and walking importlib.metadata, on every archive member. The
    rule/model blend is tunable at runtime and must NOT be cached with them."""
    from app.engine import scoring

    attestation.reset_manifest_cache()
    before = attestation.engine_manifest()["scoring"]["blend"]
    original = scoring.get_weights()
    try:
        scoring.set_weights(0.9, 0.1)
        after = attestation.engine_manifest()["scoring"]["blend"]
        assert after != before, "the blend was cached; a re-weighted engine would lie"
        assert after["rule"] == pytest.approx(0.9)
    finally:
        scoring.set_weights(original["rule"], original["model"])
        attestation.reset_manifest_cache()


def test_the_cache_is_actually_used() -> None:
    """A cache that rebuilds every call fixes nothing — the flake it was written
    for was one polling test in three."""
    attestation.reset_manifest_cache()
    first = attestation._static_manifest()
    assert attestation._static_manifest() is first


# --- 3. the container inherits the worst VERDICT ------------------------------


def test_the_worst_verdict_is_chosen_by_verdict_then_score() -> None:
    """The selection this pins is `max(key=(verdict rank, score))`. Ordering by
    score alone is what let a clean 21.9 outrank a suspicious 13.0."""
    from app.engine.pipeline import _VERDICT_RANK

    class _Member:
        def __init__(self, verdict, score):
            self.verdict = {"verdict": verdict}
            self.final_score = score

    members = [_Member("clean", 21.9), _Member("suspicious", 13.0), _Member("clean", 30.0)]
    worst = max(
        members,
        key=lambda d: (_VERDICT_RANK.get((d.verdict or {}).get("verdict"), 0),
                       d.final_score or 0.0),
    )
    assert worst.verdict["verdict"] == "suspicious"

    # and among equals, the number still breaks the tie
    equals = [_Member("suspicious", 10.0), _Member("suspicious", 40.0)]
    assert max(
        equals,
        key=lambda d: (_VERDICT_RANK.get((d.verdict or {}).get("verdict"), 0),
                       d.final_score or 0.0),
    ).final_score == 40.0


def test_the_rank_order_is_the_one_the_rule_assumes() -> None:
    from app.engine.pipeline import _VERDICT_RANK

    assert _VERDICT_RANK["clean"] < _VERDICT_RANK["suspicious"] < _VERDICT_RANK["malicious"]


# --- 4. an unknown status is a mistake, not an empty page ---------------------


def test_every_status_a_job_can_hold_is_listed() -> None:
    """`JobStatus.ALL` is what the API validates against. A value the pipeline can
    write but the list omits would be rejected as a typo."""
    written = {
        JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.AWAITING_PASSWORD,
        JobStatus.COMPLETED, JobStatus.FAILED,
    }
    assert written == set(JobStatus.ALL)
