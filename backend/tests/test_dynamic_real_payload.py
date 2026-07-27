"""The ingest path, driven by a payload a real detonation actually produced.

`data/wannacry_worker_payload.json` is the exact body `CapeV2Engine` posted for
WannaCry on our own host: 68 signals with the sandbox's categories, 18 addresses,
the suppression record and the attempted/established split. The existing ingest
tests use a hand-written body, which proves the endpoint parses what we imagined
a worker sends — not what one sends.

The distinction is not academic. Everything this file caught, a synthetic body
would have passed:

* whether a category riding on `signal.evidence` survives the round trip through
  the API schema and the database at all — if it is dropped in transit, the
  capability model is back to guessing names and nobody would notice;
* whether 68 real signals move the rating the way 3 invented ones do;
* whether `facts` we invented on the worker side (`iocs_suppressed`,
  `network_endpoints`) are preserved rather than silently discarded, since an
  analyst is told suppression is auditable.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.test_api import WORKER_TOKEN, _poll_until_done, _submit

PAYLOAD = Path(__file__).parent / "data" / "wannacry_worker_payload.json"


@pytest.fixture(scope="module")
def real_payload() -> dict:
    body = json.loads(PAYLOAD.read_text(encoding="utf-8"))
    body.pop("_source", None)
    return body


def test_the_fixture_is_a_real_detonation(real_payload) -> None:
    assert real_payload["engine"] == "capev2"
    assert real_payload["ran"] is True
    assert len(real_payload["signals"]) == 68
    with_categories = [
        s for s in real_payload["signals"] if (s.get("evidence") or {}).get("categories")
    ]
    assert len(with_categories) >= 60, "the fixture predates category capture"


@pytest.fixture()
def ingested(client, auth, real_payload):
    public_id = _submit(client, auth, "sample.exe", b"MZ" + b"\x00" * 4096)
    before = _poll_until_done(client, auth, public_id)
    response = client.post(
        f"/api/dynamic/report/{public_id}",
        json=real_payload,
        headers={"X-Worker-Token": WORKER_TOKEN},
    )
    assert response.status_code == 200, response.text
    return before, response.json()


def test_a_real_report_is_accepted_and_marks_the_tier(ingested) -> None:
    _, after = ingested
    assert after["tiers"]["dynamic"]["ran"] is True
    assert "dynamic.capev2" in after["analysis"]


def test_sixty_eight_real_signals_arrive(ingested) -> None:
    _, after = ingested
    tier = after["analysis"]["dynamic.capev2"]
    assert len(tier["signals"]) == 68


def test_the_sandbox_categories_survive_the_round_trip(ingested) -> None:
    """If evidence is flattened in transit the capability model silently regresses."""
    _, after = ingested
    signals = after["analysis"]["dynamic.capev2"]["signals"]
    with_categories = [s for s in signals if (s.get("evidence") or {}).get("categories")]
    assert len(with_categories) >= 60, (
        "categories did not survive ingest; capabilities would fall back to "
        "guessing from signal names"
    )


def test_the_verdict_reflects_a_ransomware_detonation(ingested) -> None:
    before, after = ingested
    assert after["final_score"] > before["final_score"]
    assert after["impact"]["severity"] in ("high", "critical")
    assert "/A:H" in after["impact"]["vector"]
    caps = " ".join(after["impact"].get("capabilities") or []) + json.dumps(
        after.get("verdict") or {}
    )
    assert "ransom" in caps.lower() or "destruct" in caps.lower(), (
        "a detonation with 15 ransomware-category signatures did not surface as "
        f"destructive: {caps[:200]}"
    )


def test_real_network_indicators_are_merged(ingested) -> None:
    _, after = ingested
    # Tor directory authorities WannaCry dialled. They only exist in the report
    # because dead_hosts is read - every one of these connections failed.
    assert any(ip.startswith("128.31.0.") or ip.startswith("171.25.193.")
               for ip in after["iocs"]["ips"]), after["iocs"]["ips"][:10]


def test_the_suppression_record_is_preserved(ingested) -> None:
    """An analyst is told the filter is auditable. That has to be true here."""
    _, after = ingested
    facts = after["analysis"]["dynamic.capev2"].get("facts") or {}
    suppressed = facts.get("iocs_suppressed")
    assert suppressed, f"suppression record lost on ingest; facts kept: {sorted(facts)}"
    assert suppressed["count"] > 0
    assert suppressed["entries"], "counts without entries cannot be audited"


def test_the_attempted_versus_established_split_is_preserved(ingested) -> None:
    _, after = ingested
    facts = after["analysis"]["dynamic.capev2"].get("facts") or {}
    endpoints = facts.get("network_endpoints")
    assert endpoints, "attempted/established distinction lost on ingest"
    assert endpoints["attempted"], "an isolated detonation has attempted endpoints"
