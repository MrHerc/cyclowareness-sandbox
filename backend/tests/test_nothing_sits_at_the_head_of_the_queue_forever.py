"""Two ways a job could occupy the detonation queue for ever.

The queue is oldest-first and marks nothing as claimed, so a job that can never
finish is not merely wasted work: it is served again on every poll and, being the
oldest, served FIRST. A handful of them starve the whole tier.

1. `_needs_dynamic` never looked at `sample_deleted_at`. Retention purges the
   quarantined bytes and leaves the row, which still reads "detonation has not
   run", so the worker was offered a job whose sample no longer exists,
   downloaded nothing, and was offered the same job on the next poll.

2. `process_job` returned silently when no available engine supported the
   family. No report, so the backend never learned, and round it came again.

`Report.refused_sample` already existed for this shape -- "the sandbox rejected
this sample outright, do not offer it again" -- written after eight Mirai and
Gafgyt binaries were re-offered for ever because nothing distinguished "declined"
from "not right now". A family no engine supports is declined, not delayed, so it
uses that and not `unavailable`, which `_report_blocked` correctly reserves for a
transient host problem where the job SHOULD stay eligible.

One casualty worth recording: adding the retention check failed fifty-one tests
on AttributeError, because three job stubs did not carry `sample_deleted_at`. A
stub missing a column the predicate reads does not model a row -- it models a row
that cannot exist, which is the same defect class as a fixture minting a job id
the product never mints.
"""
from __future__ import annotations

from app.api.dynamic import _needs_dynamic
from app.engine.models import JobStatus
from app.util import utcnow


class _Job:
    """Everything `_needs_dynamic` reads, including the column it learned about."""

    def __init__(self, **kw):
        self.family = kw.get("family", "pe")
        self.mime = kw.get("mime", "application/x-dosexec")
        self.original_name = kw.get("original_name", "dropper.exe")
        self.archive_path = None
        self.status = kw.get("status", JobStatus.COMPLETED)
        self.tiers = kw.get("tiers", {"dynamic": {"ran": False, "refused": False}})
        self.sample_deleted_at = kw.get("sample_deleted_at")


def test_an_ordinary_job_is_offered() -> None:
    """The control: without it the assertions below prove nothing."""
    assert _needs_dynamic(_Job()) is True


def test_a_job_whose_bytes_retention_purged_is_not_offered() -> None:
    """There is nothing left to detonate, so offering it is a loop."""
    assert _needs_dynamic(_Job(sample_deleted_at=utcnow())) is False


def test_the_purge_check_does_not_depend_on_the_tier_state() -> None:
    """Whatever the dynamic tier says, gone bytes cannot be detonated."""
    for tiers in (
        {},
        {"dynamic": {}},
        {"dynamic": {"ran": False}},
        {"dynamic": {"ran": False, "refused": False}},
    ):
        assert _needs_dynamic(_Job(tiers=tiers, sample_deleted_at=utcnow())) is False


#: The worker is a separate process and is not importable from this suite, so
#: its source is read the same way `test_the_documented_timeout_is_the_real_one`
#: reads it.
def _worker_source() -> str:
    from pathlib import Path

    return (Path(__file__).resolve().parents[2] / "worker" / "agent.py").read_text(
        encoding="utf-8")


def _block(source: str, marker: str) -> str:
    """The body of one method, up to the next `def` at method indentation."""
    start = source.index(marker)
    end = source.find(chr(10) + "    def ", start + 1)
    return source[start:end if end > 0 else len(source)]


def test_the_worker_refuses_a_family_no_engine_supports() -> None:
    """A silent return left the job at the head of the queue for ever."""
    body = _block(_worker_source(), "def process_job")
    assert "_choose_engine" in body
    assert "refused_sample" in body, (
        "process_job must POST a refusal when no engine supports the family; "
        "returning quietly leaves the job eligible and it is served again first"
    )


def test_the_refusal_is_terminal_and_the_block_is_not() -> None:
    """The two must not be confused: one is declined, the other is delayed."""
    body = _block(_worker_source(), "def _report_blocked")
    assert "unavailable" in body
    assert "refused_sample" not in body, (
        "a containment block is transient -- marking it refused would discard "
        "work because of a temporary host problem"
    )
