"""`/api/capabilities` contradicted itself, in one response.

Observed live on 65.109.28.120 on 2026-08-03:

    "static_analyzers":       [..., "virustotal"],
    "unavailable_analyzers":  {},
    "sovereignty": {"enabled": true,
                    "destinations": [{"key": "virustotal", "allowed": false}]}

An empty `unavailable_analyzers` asserts that nothing is unavailable, three keys
above a block stating that VirusTotal is refused. An operator reading the
capability panel — the endpoint this product deliberately leaves unauthenticated
so a buyer can check the posture before opening an account — concluded that hash
reputation was running. It was not, and on that deployment it could not be.

The per-sample answer was never wrong: `intel.analyze` returns
`AnalyzerResult.unavailable(name, reason)` with the true reason for every file.
Only the deployment-level claim was, which is the one read first.

`unavailable_analyzers()` had exactly one notion of unavailable — the module
failed to import. An analyzer that imports perfectly and is then refused every
call it makes is equally unable to produce a finding, and now says so.
"""
from __future__ import annotations

import pytest

from app.config import get_settings
from app.engine import analyzers


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


def _configure(monkeypatch, **env: str | None):
    """Set the environment these checks read, and clear what caches it.

    NO `sys.modules` SURGERY. An earlier version of this file deleted every
    `app.*` module to force a re-import, which is invisible when a handful of
    tests run and destructive when eighteen hundred do: every later test holding
    a reference to a class from the old module compares it against a freshly
    imported one and fails on identity. It reddened CI while passing locally.

    It is also unnecessary. `readiness()` reads `os.environ` directly,
    `native.dynamic_available()` does the same, and `sovereignty.allowed()`
    calls `get_settings()` on every invocation — so the only cache in the path
    is the settings lru_cache, and clearing that is enough.
    """
    for key, value in env.items():
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    return analyzers


def test_sovereign_mode_makes_virustotal_unavailable_not_merely_quiet(monkeypatch):
    """The live sandbox's own configuration. This is the reported defect."""
    analyzers = _configure(monkeypatch, SOVEREIGN_MODE="true", VT_API_KEY="not-used")

    assert "virustotal" in analyzers.all_names(), (
        "the analyzer is still registered — it exists, it simply cannot run"
    )
    unavailable = analyzers.unavailable_analyzers()
    assert "virustotal" in unavailable, (
        "capabilities reports VirusTotal as available on a deployment that "
        "refuses every lookup it makes"
    )
    assert "sovereign" in unavailable["virustotal"].lower()


def test_a_missing_key_is_reported_as_itself_not_as_sovereignty(monkeypatch):
    """The two reasons must not be confused.

    The refusal tally is the operator's proof of what sovereign mode actually
    stopped. A deployment that simply never configured VirusTotal must not be
    described as having been blocked by a policy it never triggered.
    """
    analyzers = _configure(monkeypatch, SOVEREIGN_MODE="false", VT_API_KEY=None)
    unavailable = analyzers.unavailable_analyzers()
    assert "virustotal" in unavailable
    assert "VT_API_KEY" in unavailable["virustotal"]
    assert "sovereign" not in unavailable["virustotal"].lower()


def test_a_configured_permitted_analyzer_is_not_flagged(monkeypatch):
    """The portal's configuration: sovereignty off, key present.

    A readiness check that fires when the analyzer genuinely works is worse than
    none — it teaches the reader to ignore the field.
    """
    analyzers = _configure(monkeypatch, SOVEREIGN_MODE="false", VT_API_KEY="configured")
    # About virustotal specifically, NOT `== {}`. A different analyzer failing to
    # import is a real and separate condition — an environment without libmagic
    # has one — and folding it into this assertion makes the test fail for a
    # reason it is not about.
    assert "virustotal" not in analyzers.unavailable_analyzers()


def test_analyzers_without_a_readiness_check_are_assumed_ready(monkeypatch):
    """Every other analyzer is pure static parsing with nothing to withhold, so
    none declares `readiness()`. Absence must mean ready, never unknown."""
    analyzers = _configure(monkeypatch, SOVEREIGN_MODE="false", VT_API_KEY="configured")
    unavailable = analyzers.unavailable_analyzers()
    for name in analyzers.all_names():
        if name == "virustotal":
            continue
        assert name not in unavailable


def test_a_raising_readiness_check_cannot_take_the_endpoint_down(monkeypatch):
    """`/api/capabilities` is the page an auditor is pointed at. A probe that
    throws must degrade to a stated reason, never to a 500."""
    analyzers = _configure(monkeypatch, SOVEREIGN_MODE="false", VT_API_KEY="configured")
    entry = next(e for e in analyzers.registry() if e.name == "virustotal")

    def explode() -> str:
        raise RuntimeError("probe blew up")

    monkeypatch.setattr(entry.module, "readiness", explode)
    unavailable = analyzers.unavailable_analyzers()
    assert "virustotal" in unavailable
    assert "RuntimeError" in unavailable["virustotal"]


@pytest.mark.parametrize("sovereign", ["true", "false"])
def test_the_capability_endpoint_never_contradicts_its_own_sovereignty_block(
    monkeypatch, sovereign
):
    """The assertion the reported defect violated, stated directly.

    Whatever the posture, an analyzer named as permitted-and-configured must not
    appear in `unavailable_analyzers`, and one the sovereignty block refuses
    must not be absent from it.
    """
    monkeypatch.setenv("VT_API_KEY", "configured")
    analyzers = _configure(monkeypatch, SOVEREIGN_MODE=sovereign, VT_API_KEY="configured")
    from app import sovereignty

    permitted = sovereignty.allowed("virustotal")
    flagged = "virustotal" in analyzers.unavailable_analyzers()
    assert permitted != flagged, (
        f"sovereignty says allowed={permitted} while capabilities says "
        f"unavailable={flagged} — the same response disagreeing with itself"
    )
