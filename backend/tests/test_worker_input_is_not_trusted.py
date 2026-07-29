"""The widest input this product takes from another machine.

`DynamicReportIn.facts`, a signal's `evidence` and the timeline are all
`dict[str, Any]`, so whatever the detonation worker puts there is what gets
written to the job row. `json.loads` accepts `NaN` and `Infinity` — they are
what `json.dumps` emits by default — and Starlette hard-codes `allow_nan=False`
on the way out.

So one `NaN` in `facts` was accepted with a 200, and afterwards `export.json`
and `export.signed` returned **500 for that job permanently**: the signed
evidence copy `attestation.py` exists to produce, unreachable, because of a
number in a free-form dict.

A very large integer was the same failure with a different shape.
`extract_features` does `float(value)` on `facts["max_section_entropy"]`, and
`float()` on an integer too large for a float raises OverflowError — the ingest
500'd, and because the job stayed `completed` the queue offered it to the worker
again on every poll, forever.
"""
from __future__ import annotations

import json

import pytest

from tests.test_api import WORKER_TOKEN, _poll_until_done, _submit

BASE = {
    "engine": "capev2",
    "worker": "detonation-01",
    "ran": True,
    "unavailable_reason": None,
    "refused": False,
    "signals": [],
    "facts": {},
    "iocs": {},
    "duration_ms": 1000,
    "timeline": [],
}

EXPORTS = ["export.json", "export.stix", "export.incident", "export.signed"]


def _detonated(client, auth, facts=None, signals=None, timeline=None):
    public_id = _submit(client, auth, "loader.exe", b"MZ" + b"\x00" * 8192)
    _poll_until_done(client, auth, public_id)
    body = dict(BASE)
    if facts is not None:
        body["facts"] = facts
    if signals is not None:
        body["signals"] = signals
    if timeline is not None:
        body["timeline"] = timeline
    # Raw bytes: the test client refuses to encode NaN, and the worker that
    # found this did not use the test client.
    text = json.dumps(body).replace('"__NAN__"', "NaN").replace('"__INF__"', "Infinity")
    response = client.post(
        f"/api/dynamic/report/{public_id}",
        content=text,
        headers={"X-Worker-Token": WORKER_TOKEN, "Content-Type": "application/json"},
    )
    assert response.status_code == 200, response.text
    return public_id


@pytest.mark.parametrize("payload", [
    {"guest_cpu_pct": "__NAN__"},
    {"guest_cpu_pct": "__INF__"},
    {"nested": {"deep": {"value": "__NAN__"}}},
    {"series": [1.0, "__NAN__", 3.0]},
    {"max_section_entropy": "__INF__"},
])
def test_a_non_finite_number_never_makes_an_export_unreadable(client, auth, payload) -> None:
    public_id = _detonated(client, auth, facts=payload)
    for name in EXPORTS:
        response = client.get(f"/api/jobs/{public_id}/{name}", headers=auth)
        assert response.status_code == 200, f"{name} -> {response.status_code}"
    assert client.get(f"/api/result/{public_id}", headers=auth).status_code == 200
    assert client.get("/api/jobs?limit=1", headers=auth).status_code == 200


def test_the_observation_is_kept_as_text_not_dropped(client, auth) -> None:
    """Losing the finding to protect the serialiser trades one silent wrong
    answer for another. An analyst should still see the worker said `inf`."""
    public_id = _detonated(client, auth, facts={"guest_cpu_pct": "__INF__"})
    facts = client.get(f"/api/result/{public_id}", headers=auth).json()["dynamic"]["facts"]
    assert facts["guest_cpu_pct"] == "inf", facts


def test_a_huge_integer_does_not_500_the_ingest(client, auth) -> None:
    """`float(10**400)` raises OverflowError inside extract_features, and the
    job then stayed `completed`, so the queue re-offered it on every poll."""
    public_id = _detonated(client, auth, facts={"max_section_entropy": 10**400})
    detail = client.get(f"/api/result/{public_id}", headers=auth).json()
    assert detail["tiers"]["dynamic"]["ran"] is True
    assert isinstance(detail["final_score"], float)


def test_non_finite_evidence_on_a_signal_is_handled_too(client, auth) -> None:
    public_id = _detonated(client, auth, signals=[{
        "id": "capev2.made_up", "title": "t", "severity": "high", "detail": "",
        "evidence": {"ratio": "__NAN__"},
    }])
    for name in EXPORTS:
        assert client.get(f"/api/jobs/{public_id}/{name}", headers=auth).status_code == 200


def test_a_non_finite_timeline_entry_is_handled_too(client, auth) -> None:
    public_id = _detonated(client, auth, timeline=[{"t": "__NAN__", "event": "start"}])
    assert client.get(f"/api/result/{public_id}", headers=auth).status_code == 200
    for name in EXPORTS:
        assert client.get(f"/api/jobs/{public_id}/{name}", headers=auth).status_code == 200


def test_the_entropy_feature_clamps_instead_of_raising() -> None:
    """Directly, because this is the arithmetic the report reaches."""
    from app.engine.scoring import _as_entropy

    # Nothing that is not a finite measurement may push the score UP: whatever
    # wrote this dict would otherwise inflate a verdict by sending a non-number.
    assert _as_entropy(10**400) == 0.0
    assert _as_entropy(float("inf")) == 0.0
    assert _as_entropy(float("-inf")) == 0.0
    assert _as_entropy(float("nan")) == 0.0
    assert _as_entropy(-5.0) == 0.0
    assert _as_entropy(99.0) == 8.0
    assert _as_entropy(7.2) == pytest.approx(7.2)
    assert _as_entropy("7.2") == 0.0
    assert _as_entropy(None) == 0.0
    assert _as_entropy(True) == 0.0


# --- and the timeline cannot blank the report page ---------------------------


@pytest.mark.parametrize("kind", [
    {"nested": "object"},
    ["a", "list"],
    12345,
    None,
    True,
])
def test_a_non_string_timeline_kind_cannot_reach_the_ui(client, auth, kind) -> None:
    """`BehaviorGraph` renders `{kind}` straight into JSX. An object there is
    "Objects are not valid as a React child", which unmounts the whole tree —
    the report page goes permanently blank, and so does every page the router
    renders after it, from a 200 the API accepted without complaint."""
    public_id = _detonated(client, auth, timeline=[{"t_ms": 10, "kind": kind, "detail": "x"}])
    timeline = client.get(f"/api/result/{public_id}", headers=auth).json()["dynamic"]["timeline"]
    assert timeline, "the entry was dropped entirely"
    entry = timeline[0]
    assert isinstance(entry["kind"], str) and entry["kind"], entry
    assert isinstance(entry["detail"], str)
    assert isinstance(entry["t_ms"], int)


def test_a_nonsense_timestamp_does_not_break_the_axis(client, auth) -> None:
    public_id = _detonated(client, auth, timeline=[
        {"t_ms": "not a number", "kind": "process", "detail": "d"},
        {"t_ms": -50, "kind": "network", "detail": "d"},
        {"t_ms": 10**30, "kind": "file", "detail": "d"},
    ])
    timeline = client.get(f"/api/result/{public_id}", headers=auth).json()["dynamic"]["timeline"]
    assert all(isinstance(e["t_ms"], int) and e["t_ms"] >= 0 for e in timeline), timeline


def test_a_flood_of_events_is_bounded(client, auth) -> None:
    """A hundred thousand events is an SVG with a hundred thousand circles in
    it: a blank tab and a pinned CPU on the analyst's laptop."""
    public_id = _detonated(client, auth, timeline=[
        {"t_ms": n, "kind": "process", "detail": "d"} for n in range(5000)
    ])
    timeline = client.get(f"/api/result/{public_id}", headers=auth).json()["dynamic"]["timeline"]
    assert 0 < len(timeline) <= 2000, len(timeline)
