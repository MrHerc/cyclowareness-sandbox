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


# --- the path that took the whole dynamic tier down -------------------------


def test_a_family_no_engine_supports_is_refused_not_crashed(agent) -> None:
    """`process_job` called `self._deliver(...)`, and `_deliver` did not exist.

    It was written as the fix for "a job that can never finish occupies the head
    of an oldest-first queue for ever", and it was latent for as long as every
    family the backend offered happened to be claimed by the CAPE engine. Adding
    `rtf` and `lnk` to `_DYNAMIC_FAMILIES` — with the analyzers, and without
    widening `supports()` — made it reachable.

    What it cost, measured on the live worker: `AttributeError` raised inside
    `pool.map`, which re-raises on the first future, so the ENTIRE batch died
    every cycle. 1176 loop errors, one every sixteen seconds, nine `lnk`/`rtf`
    jobs pinned at the head, and every `pe`, `pdf` and `office` job behind them
    never detonated. Nothing in the product reported a fault; the dynamic tier
    simply stopped.

    Stubbed at `_post_json` like every other test here, so this asserts the
    contract — a job nothing can run is REPORTED and leaves the queue — rather
    than the shape of the method that does it.
    """
    agent._choose_engine = lambda family: None

    agent.process_job({**JOB, "family": "obscure-format", "suffix": ".xyz"})

    assert agent.posted, "a job no engine can run must still be reported"
    path, body = agent.posted[-1]
    assert path.endswith("/job-abc")
    assert body["ran"] is False
    assert body.get("refused") is True, (
        "declined, not delayed: leaving it eligible is what pins it to the head "
        "of the queue"
    )
    assert "obscure-format" in (body.get("unavailable_reason") or "")


def test_the_batch_survives_one_unrunnable_job(agent) -> None:
    """The reason the crash was catastrophic rather than annoying.

    `run_once` maps `process_job` over the whole page. One raising job took the
    other jobs on that page with it — so a handful of undetonatable shortcuts
    stopped every executable behind them.
    """
    calls = []
    real = agent.process_job

    def _choose(family):
        return None if family == "lnk" else agent.engine
    agent._choose_engine = _choose

    for family, suffix in (("lnk", ".lnk"), ("rtf", ".rtf"), ("pe", ".exe")):
        real({**JOB, "family": family, "suffix": suffix})
        calls.append(family)

    assert calls == ["lnk", "rtf", "pe"]
    assert agent.engine.calls, "the runnable job must still have been detonated"


def test_the_worker_claims_every_family_the_backend_offers() -> None:
    """The two sets are one decision written in two files, and they drifted.

    A family the queue offers and no engine claims is not a missing feature —
    it is a job that comes back on every poll for ever.
    """
    import re

    root = Path(__file__).resolve().parents[2]
    offered = set(re.search(
        r"_DYNAMIC_FAMILIES\s*=\s*\{([^}]*)\}",
        (root / "backend" / "app" / "api" / "dynamic.py").read_text(encoding="utf-8"),
    ).group(1).replace('"', "").replace("'", "").replace(" ", "").split(","))
    offered.discard("")

    claimed = set(re.search(
        r"return family in \{([^}]*)\}",
        (root / "worker" / "engines" / "opensource.py").read_text(encoding="utf-8"),
    ).group(1).replace('"', "").replace("'", "").replace(" ", "").split(","))
    claimed.discard("")

    assert offered <= claimed, (
        "the backend offers families no engine claims: "
        f"{sorted(offered - claimed)}"
    )
