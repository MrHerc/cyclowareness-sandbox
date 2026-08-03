"""`/api/capabilities` promised a detonation tier its own ingest seam refused.

`dynamic_worker` was `native.dynamic_available()` — the `SANDBOX_DYNAMIC_WORKER`
flag alone. `require_worker` refuses every queue, sample and report request with

    503 Dynamic ingest is not enabled on this deployment (no worker token set)

whenever `DYNAMIC_WORKER_TOKEN` is empty. So a deployment with the flag set and
no token advertised behavioural analysis on the one endpoint this product
deliberately leaves unauthenticated — the page a buyer reads before they have an
account — while nothing could ever be detonated.

The tests below assert the relationship rather than the two values, because that
is the property that must hold: **the capability panel and the gate are answers
to the same question, and they may never disagree.** A future change that opens
the gate on a third condition fails here until the panel learns about it too.
"""
from __future__ import annotations

import pytest

from app.api.dynamic_state import dynamic_state
from app.config import get_settings


@pytest.fixture(autouse=True)
def _restore_settings_cache():
    """Clear the settings cache on the way OUT as well as in.

    `get_settings` is an lru_cache. A test that clears it, sets an environment
    and calls it leaves the cache holding a Settings built from that
    environment; monkeypatch then restores the environment and the next test
    reads the stale object. Clearing on teardown is what makes these tests safe
    to run in the middle of eighteen hundred others.
    """
    yield
    get_settings.cache_clear()


def _state(monkeypatch, *, flag: str | None, token: str | None):
    """Evaluate the state under a given environment.

    No module reloading: `native.dynamic_available()` reads `os.environ` on every
    call and the only cache in the path is the settings lru_cache. Purging
    `sys.modules` mid-suite breaks every later test that holds a reference to a
    class from the module being replaced.
    """
    if flag is None:
        monkeypatch.delenv("SANDBOX_DYNAMIC_WORKER", raising=False)
    else:
        monkeypatch.setenv("SANDBOX_DYNAMIC_WORKER", flag)
    if token is None:
        monkeypatch.delenv("DYNAMIC_WORKER_TOKEN", raising=False)
    else:
        monkeypatch.setenv("DYNAMIC_WORKER_TOKEN", token)

    get_settings.cache_clear()
    return dynamic_state(get_settings())


@pytest.mark.parametrize(
    "flag,token",
    [(None, None), ("1", None), (None, "a-token"), ("1", "a-token")],
)
def test_the_capability_never_disagrees_with_the_ingest_gate(monkeypatch, flag, token):
    """The property, stated directly.

    `require_worker` accepts exactly when a token is configured. The capability
    may be true only when the gate would accept — advertising a tier the gate
    refuses is the defect this file exists for. It may also be false while the
    gate would accept, and that is not a contradiction: a token without declared
    hardware is a credential with nothing behind it.
    """
    available, reason = _state(monkeypatch, flag=flag, token=token)
    gate_accepts = bool((token or "").strip())

    if available:
        assert gate_accepts, (
            "capabilities advertises a detonation tier while require_worker "
            "would answer 503 to every request the worker makes"
        )
        assert reason is None, "an available tier must not also carry a reason it is not"
    else:
        assert reason, "an unavailable tier must say what is missing, not merely say no"


def test_the_flag_alone_does_not_open_the_tier(monkeypatch):
    """The reported defect, pinned.

    This is the state the live deployment could reach: hardware declared, no
    credential for it to report back with.
    """
    available, reason = _state(monkeypatch, flag="1", token=None)
    assert available is False
    assert "DYNAMIC_WORKER_TOKEN" in reason
    assert "Nothing has been detonated" in reason


def test_the_token_alone_does_not_open_the_tier(monkeypatch):
    """A token is a credential, not hardware.

    The flattering reading — "a token is configured, so someone must have set up
    a worker" — is the one that produces two screens making opposite claims about
    whether hostile code was executed.
    """
    available, reason = _state(monkeypatch, flag=None, token="a-token")
    assert available is False
    assert "SANDBOX_DYNAMIC_WORKER" in reason


def test_both_switches_open_it(monkeypatch):
    available, reason = _state(monkeypatch, flag="1", token="a-token")
    assert available is True
    assert reason is None


def test_each_half_configured_state_gets_its_own_reason(monkeypatch):
    """"No worker attached" and "a worker is attached but cannot report" send an
    operator to two different places. One reason for both would be useless."""
    _, no_flag = _state(monkeypatch, flag=None, token="a-token")
    _, no_token = _state(monkeypatch, flag="1", token=None)
    _, neither = _state(monkeypatch, flag=None, token=None)
    assert len({no_flag, no_token, neither}) == 3


def test_the_capability_endpoint_publishes_the_reason(monkeypatch):
    """A bare `false` tells an operator nothing. The endpoint carries the reason
    so the screen can say which switch is missing."""
    monkeypatch.setenv("SANDBOX_DYNAMIC_WORKER", "1")
    monkeypatch.delenv("DYNAMIC_WORKER_TOKEN", raising=False)
    get_settings.cache_clear()

    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        body = client.get("/api/capabilities").json()

    assert body["dynamic_worker"] is False
    assert body["dynamic_unavailable_reason"], (
        "the endpoint reports the tier as unavailable without saying why"
    )
