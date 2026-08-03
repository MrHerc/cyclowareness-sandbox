"""No engine row may publish a severity the score did not allow.

This is the eighth leak of the same guard. The previous seven were the score,
the ATT&CK mapping, the impact rating, the threat name, the identification
branch, the indicator count and the tier text -- each one a different consumer
forgetting a filter, each one found by a different audit.

The eighth was `verdict._worst`. It forwarded `family` (the calibration axis)
and not `dynamic_attributable` (the "Windows cannot run this file, so the
guest's behaviour is the guest's" axis), so the `CS-dynamic.capev2` row carried
the raw CAPE severity on exactly the samples the engine had decided may not
accuse. Measured over 839 detonated jobs: 90 rows stored `high` where the score
had banded every one of their signals `low`. One of them is a file called
LICENSE, and its signed evidence bundle publishes `"severity": "high"` three
keys away from a block stating those findings are excluded from the score.

So these tests do not assert on a line number or a call site. They assert the
INVARIANT -- for every engine row, the published severity is bounded by what
`effective_severity` allows for that row's own signals under the same two axes.
A ninth consumer added tomorrow fails here without anyone remembering to come
back and add a case.

A symmetry test between `pipeline.run` and `api/dynamic.ingest_report` cannot
catch this class: both paths call the same `_worst`, so both were wrong in the
same way and agreed with each other perfectly.
"""
from __future__ import annotations

import pytest

from app.engine import scoring, verdict
from app.engine.contracts import SEVERITY_ORDER, AnalyzerResult, IOCs, Signal


def _sig(sid: str, severity: str = "high") -> Signal:
    return Signal(id=sid, title=sid.replace(".", " "), severity=severity, detail="", evidence={})


#: What a real detonation of an inert file produces -- the six ids from the live
#: LICENSE job, at the severities CAPE actually assigned them.
TRACE = [
    _sig("capev2.queries_locale_api"),
    _sig("capev2.antidebug_setunhandledexceptionfilter"),
    _sig("capev2.stealth_timeout"),
    _sig("capev2.query_fips_reconnaissance"),
    _sig("capev2.discover_registry_mount_points"),
    _sig("capev2.process_creation_suspicious_location"),
]


def _classify(*, attributable: bool, family: str = "script"):
    return verdict.classify(
        family,
        "text/plain",
        [AnalyzerResult(analyzer="dynamic.capev2", ran=True, signals=list(TRACE))],
        IOCs(),
        0.0,
        attributable=attributable,
    )


def _rows(result):
    return {r["engine"]: r for r in (result.engines or [])}


def test_an_unattributable_trace_does_not_publish_a_high_row() -> None:
    """The defect itself, at the value that shipped."""
    row = _rows(_classify(attributable=False))["CS-dynamic.capev2"]
    assert row["severity"] == "low", row
    assert row["detected"] is False, row


def test_an_attributable_trace_still_publishes_what_the_sandbox_saw() -> None:
    """The control. This is a statement about files Windows cannot run, not a
    way to quieten the dynamic tier -- a PE that really executed keeps its
    severity."""
    row = _rows(_classify(attributable=True, family="pe"))["CS-dynamic.capev2"]
    assert row["severity"] == "high", row


@pytest.mark.parametrize("attributable", [True, False])
@pytest.mark.parametrize("family", ["pe", "script", "elf"])
def test_no_row_outranks_what_the_score_allowed(attributable: bool, family: str) -> None:
    """THE INVARIANT. Every row, every axis combination, no exceptions.

    The bound is computed the same way the score computes it, from the same
    function, so this cannot drift apart from the scoring rules the way a
    hard-coded expectation would.
    """
    result = _classify(attributable=attributable, family=family)
    alone = scoring.uncorroborated(TRACE)
    signed = scoring.publisher_verified(TRACE)
    allowed = max(
        (
            scoring.effective_severity(
                s, alone,
                verified_publisher=signed,
                family=family,
                dynamic_attributable=attributable,
            )
            for s in TRACE
        ),
        key=lambda sev: SEVERITY_ORDER.get(sev, 0),
    )
    ceiling = SEVERITY_ORDER.get(allowed, 0)

    for name, row in _rows(result).items():
        published = SEVERITY_ORDER.get(row.get("severity", "info"), 0)
        assert published <= ceiling, (
            f"{name} publishes {row.get('severity')} on family={family} "
            f"attributable={attributable}, but the score allowed at most {allowed}"
        )


def test_the_axis_actually_reaches_worst() -> None:
    """A direct check on the helper, so a future refactor that drops the keyword
    argument fails here with a clear message rather than as a subtle change in
    an engine row three functions away."""
    assert verdict._worst(TRACE, "script", dynamic_attributable=True) == "high"
    assert verdict._worst(TRACE, "script", dynamic_attributable=False) == "low"


def test_every_worst_call_site_threads_an_axis() -> None:
    """Mechanical, and deliberately so.

    Any `_worst(` call inside `classify` must either pass `dynamic_attributable`
    or operate on a list the exclusions were already applied to. Rather than
    encoding which is which -- that list is exactly what goes stale -- this
    asserts the count of raw-signal call sites, so ADDING one without a keyword
    argument turns this red and makes the author state their case.
    """
    import inspect

    source = inspect.getsource(verdict.classify)
    calls = [line.strip() for line in source.splitlines() if "_worst(" in line]
    unguarded = [
        c for c in calls
        if "dynamic_attributable" not in c
        and not any(safe in c for safe in ("identification", "bad_rep", "admissible"))
    ]
    assert not unguarded, (
        "a `_worst` call in classify() reads signals without threading the "
        f"attributability axis: {unguarded}"
    )
