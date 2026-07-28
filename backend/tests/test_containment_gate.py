"""The worker refuses to detonate on a host it cannot prove is contained.

Before this existed there was no containment check anywhere in the worker — a
grep for containment/isolation/egress across `worker/` returned one unrelated
comment. The procedure was "run verify-containment.sh before every real-malware
run", which is a human step, and a human step is not containment.

It also could not have worked as a per-run check, because containment was not a
stable property. The rules lived in the iptables FORWARD chain and CAPE's rooter
re-inserts an ACCEPT at position 1 on every SIGTERM, so a host verified at time T
could be open at T+1. Containment now lives in a separate nftables table whose
hooks run first regardless of what anyone inserts, and this gate's job is to
prove that is still true immediately before each batch.

The invariant: **absent evidence is not success.** A timeout, a missing command,
a crash, a non-zero exit and an unparseable answer all mean *not contained*. The
in-guest verifier once certified a host on a single line of output having tested
nothing, and that is the failure this file exists to prevent.
"""
from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

import pytest

WORKER = Path(__file__).resolve().parents[2] / "worker"


def _check(body: str) -> str:
    """A containment check that runs `body` in this interpreter.

    Built with shlex.quote so it survives the shlex.split the gate does, on any
    platform and whatever the interpreter path contains.
    """
    return f"{shlex.quote(sys.executable)} -c {shlex.quote(body)}"


def _says(payload: dict, exit_code: int = 0) -> str:
    return _check(
        f"import sys; print({json.dumps(json.dumps(payload))}); sys.exit({exit_code})"
    )


@pytest.fixture()
def agent_for(monkeypatch):
    """An Agent with no engines and a stubbed HTTP seam."""
    sys.path.insert(0, str(WORKER))
    try:
        import agent as agent_mod  # type: ignore
        from config import Config  # type: ignore

        def build(command: str, **kwargs):
            config = Config(
                api_url="http://backend.invalid",
                worker_token="t",
                containment_check=command,
                **kwargs,
            )
            monkeypatch.setattr(agent_mod.Agent, "_build_engines", lambda self: [])
            instance = agent_mod.Agent(config)
            instance.posted = []
            monkeypatch.setattr(
                instance, "_post_json",
                lambda path, body: instance.posted.append((path, body)),
            )
            return instance

        yield build
    finally:
        sys.path.remove(str(WORKER))


def _queue(agent, monkeypatch, jobs):
    monkeypatch.setattr(agent, "_get_json", lambda path: jobs)
    processed = []
    monkeypatch.setattr(agent, "process_job", lambda job: processed.append(job))
    return processed


JOBS = [{"public_id": "job-a", "family": "pe"}, {"public_id": "job-b", "family": "pe"}]


def test_a_contained_host_detonates(agent_for, monkeypatch) -> None:
    agent = agent_for(_says({"contained": True}))
    processed = _queue(agent, monkeypatch, JOBS)
    assert agent.run_once() == 2
    assert len(processed) == 2


@pytest.mark.parametrize(
    "command,label",
    [
        (_check("raise SystemExit(1)"), "non-zero exit"),
        ("/nonexistent/containment-check", "missing command"),
        (_check("import sys; sys.exit(3)"), "unexpected exit code"),
        (_check("print('not json at all'); raise SystemExit(1)"), "unparseable answer"),
    ],
)
def test_an_uncontained_host_detonates_nothing(agent_for, monkeypatch, command, label) -> None:
    agent = agent_for(command)
    processed = _queue(agent, monkeypatch, JOBS)
    assert agent.run_once() == 0, label
    assert processed == [], f"{label}: a sample was detonated on an unverified host"


def test_a_check_that_exits_zero_but_says_no_is_disbelieved(agent_for, monkeypatch) -> None:
    """A broken check must not be able to certify a host by exiting 0."""
    agent = agent_for(_says({"contained": False, "reason": "table absent"}))
    processed = _queue(agent, monkeypatch, JOBS)
    assert agent.run_once() == 0
    assert processed == []


def test_a_hanging_check_fails_closed(agent_for, monkeypatch) -> None:
    """A gate that hangs must block, not wait forever and then let everything by."""
    agent = agent_for(
        _check("import time; time.sleep(30)"), containment_check_timeout_seconds=1
    )
    processed = _queue(agent, monkeypatch, JOBS)
    assert agent.run_once() == 0
    assert processed == []
    contained, reason = agent.check_containment()
    assert contained is False
    assert "timed out" in reason


def test_a_blocked_batch_is_reported_not_silently_dropped(agent_for, monkeypatch) -> None:
    """The operator must see held jobs, never a queue that quietly stops."""
    agent = agent_for(_check("raise SystemExit(1)"))
    _queue(agent, monkeypatch, JOBS)
    agent.run_once()

    assert len(agent.posted) == 2, "a refused batch reported nothing"
    for path, body in agent.posted:
        assert path.startswith("/api/dynamic/report/")
        assert body["ran"] is False
        assert "Not detonated" in body["unavailable_reason"]
        # NOT terminal: the sandbox never saw these samples, so they must run as
        # soon as the host is safe. Marking them refused would discard work over
        # a transient host problem.
        assert body["refused"] is False


def test_no_check_configured_still_runs(agent_for, monkeypatch) -> None:
    """A Qiling-only laptop confines by construction and must not be blocked."""
    agent = agent_for("")
    processed = _queue(agent, monkeypatch, JOBS)
    assert agent.run_once() == 2
    assert len(processed) == 2
    contained, reason = agent.check_containment()
    assert contained is True
    assert "no containment check configured" in reason


def test_an_empty_queue_does_not_probe_containment(agent_for, monkeypatch) -> None:
    """The common case is an empty poll; it must not spawn a subprocess."""
    agent = agent_for("/nonexistent/containment-check")
    calls = []
    monkeypatch.setattr(agent, "check_containment", lambda: calls.append(1) or (True, ""))
    monkeypatch.setattr(agent, "_get_json", lambda path: [])
    assert agent.run_once() == 0
    assert calls == []
