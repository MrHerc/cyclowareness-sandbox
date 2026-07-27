"""The worker's own loop — the thing we actually ship, and the thing nothing tested.

Every detonation so far was driven by calling `CapeV2Engine.run()` directly from
a harness. That proves the engine. It does not prove `Agent.process_job`, which
is what runs in production: claim a job, fetch the bytes, name the file, pick an
engine, post the report, clean up.

The gap mattered most for the file name. The backend now returns a sanitised
`suffix` on the queue entry precisely because a sandbox chooses its analysis
package from the file name — and if the worker drops it on the way to disk, the
whole fix is inert and every report quietly gets thinner. Nothing would fail;
the numbers would just be worse.

I/O is stubbed at the three seams the Agent already has (`_get_json`,
`_download`, `_post_json`) rather than by patching internals, so these tests
describe the contract rather than the implementation.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

WORKER = Path(__file__).resolve().parents[2] / "worker"


@pytest.fixture()
def agent_mod():
    sys.path.insert(0, str(WORKER))
    try:
        import agent as mod  # type: ignore

        yield mod
    finally:
        sys.path.remove(str(WORKER))


class _RecordingEngine:
    """Stands in for a detonation backend and remembers how it was called."""

    name = "capev2"

    def __init__(self):
        self.calls = []

    def available(self) -> bool:
        return True

    def supports(self, family: str) -> bool:
        return True

    def run(self, sample_path, sha256, family):
        from engines.base import Report  # type: ignore

        self.calls.append({"path": sample_path, "sha256": sha256, "family": family})
        rep = Report(engine=self.name, worker="test-worker")
        rep.add_signal("capev2.ransomware_file_modifications", "mass file writes", "high")
        rep.add_ioc("ips", "203.0.113.9")
        rep.facts["task_id"] = 42
        return rep


@pytest.fixture()
def agent(agent_mod):
    """An Agent with its three I/O seams replaced and one recording engine."""
    import dataclasses

    from config import Config  # type: ignore

    # Config is frozen on purpose - a worker's endpoint and token should not be
    # mutable at runtime - so build the variant rather than assigning to it.
    cfg = dataclasses.replace(
        Config(),
        api_url="http://backend.invalid",
        worker_token="t",
        worker_name="test-worker",
        http_timeout_seconds=5,
        poll_interval_seconds=0,
        engine_timeout_seconds=5,
    )

    a = agent_mod.Agent.__new__(agent_mod.Agent)
    a.config = cfg
    a._requests = None
    a.engine = _RecordingEngine()
    a.engines = [a.engine]
    a.posted = []
    a.downloaded_to = []

    a._get_json = lambda path: a.queue_response
    def _download(path, dest):
        a.downloaded_to.append(dest)
        with open(dest, "wb") as fh:
            fh.write(b"MZ" + b"\x00" * 64)
    a._download = _download
    a._post_json = lambda path, body: a.posted.append((path, body))
    a._choose_engine = lambda family: a.engine
    return a


JOB = {
    "public_id": "job-abc",
    "sha256": "a" * 64,
    "family": "pe",
    "size_bytes": 66,
    "sample_url": "/api/dynamic/sample/job-abc",
}


def test_the_extension_from_the_queue_reaches_the_engine(agent) -> None:
    """The whole point of the backend's `suffix` field."""
    agent.process_job({**JOB, "suffix": ".ps1"})
    assert agent.engine.calls, "the engine was never invoked"
    used = agent.engine.calls[0]["path"]
    assert used.endswith(".ps1"), f"suffix dropped on the way to disk: {used}"


def test_an_older_backend_without_suffix_still_works(agent) -> None:
    """`suffix` is additive; a worker must not require it."""
    agent.process_job(dict(JOB))
    assert agent.engine.calls
    assert os.path.splitext(agent.engine.calls[0]["path"])[1] == ""


@pytest.mark.parametrize("suffix", ["", None])
def test_empty_suffix_is_tolerated(agent, suffix) -> None:
    agent.process_job({**JOB, "suffix": suffix})
    assert agent.engine.calls


def test_the_report_is_posted_to_the_right_job(agent) -> None:
    agent.process_job({**JOB, "suffix": ".exe"})
    assert len(agent.posted) == 1
    path, body = agent.posted[0]
    assert path == "/api/dynamic/report/job-abc"
    assert body["engine"] == "capev2"
    assert body["ran"] is True
    assert body["signals"][0]["id"] == "capev2.ransomware_file_modifications"
    assert "203.0.113.9" in body["iocs"]["ips"]


def test_the_sample_is_removed_from_disk_afterwards(agent) -> None:
    """The worker holds live malware; leaving it behind fills the box and is a
    hazard on a machine that is not supposed to accumulate samples."""
    agent.process_job({**JOB, "suffix": ".exe"})
    assert agent.downloaded_to
    for p in agent.downloaded_to:
        assert not os.path.exists(p), f"sample left behind at {p}"


def test_a_crashing_engine_does_not_kill_the_loop(agent) -> None:
    """An engine that raises must become an honest ran=False, not a dead worker."""
    def boom(*_a, **_k):
        raise RuntimeError("detonation host on fire")
    agent.engine.run = boom
    agent.process_job({**JOB, "suffix": ".exe"})
    # Either it posted an unavailable report or it swallowed the job; it must not
    # have raised, and it must not have posted a report claiming success.
    for _path, body in agent.posted:
        assert body["ran"] is False
        assert body["unavailable_reason"]


def test_a_job_without_a_public_id_is_ignored(agent) -> None:
    agent.process_job({"sha256": "b" * 64, "family": "pe"})
    assert not agent.posted
    assert not agent.engine.calls
