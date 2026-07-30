"""The sovereignty promise is made by the web service and kept by two processes.

`/api/capabilities` reports `cuckoo`, `capev2` and `joesandbox` as **Blocked**
under sovereign mode. Nothing in the backend can reach any of them: they are the
worker's engines, and the worker is a separate program that does not import
`app.sovereignty` and never asked it anything. So with `SOVEREIGN_MODE=true` and
`CAPEV2_URL` set — the shipped compose file sets both — the screen said the
sample file was going nowhere while the worker uploaded it.

The fix is a second choke point in the worker reading the same variable. That is
not as good as one choke point and it is the best available: two OS processes
cannot share a Python module, and a promise about egress has to be kept in the
process that has the socket.

These tests import the worker the way the other worker tests do, from the
sibling directory, so the backend suite covers the program it ships next to.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

WORKER = Path(__file__).resolve().parents[2] / "worker"


@pytest.fixture()
def worker():
    """(config module, opensource engines module)."""
    sys.path.insert(0, str(WORKER))
    try:
        import config as config_mod  # type: ignore
        from engines import opensource  # type: ignore

        yield config_mod, opensource
    finally:
        sys.path.remove(str(WORKER))


def _configured(config_mod, **overrides):
    """A worker config with every upload engine pointed at something."""
    base = dict(
        worker_token="t",
        cuckoo_url="http://cuckoo.internal",
        capev2_url="http://cape.internal",
        joe_url="http://joe.example",
        joe_apikey="k",
    )
    base.update(overrides)
    return config_mod.Config(**base)


ENGINES = ["CuckooEngine", "CapeV2Engine", "JoeSandboxEngine"]


@pytest.mark.parametrize("engine_name", ENGINES)
def test_sovereign_mode_makes_an_upload_engine_unavailable(worker, engine_name) -> None:
    """The finding, one engine at a time."""
    config_mod, opensource = worker
    config = _configured(config_mod, sovereign_mode=True)
    engine = getattr(opensource, engine_name)(config)

    assert not engine.available(), (
        f"{engine_name} is configured and sovereign mode is on, and it still "
        "offered to upload the sample"
    )


@pytest.mark.parametrize("engine_name", ENGINES)
def test_running_one_anyway_refuses_before_it_opens_the_file(worker, engine_name, tmp_path) -> None:
    """`available()` is what the agent checks; this is the lock behind it.

    The sample path does not exist: if the refusal did not come first, the engine
    would open it and fail with something else.
    """
    config_mod, opensource = worker
    config = _configured(config_mod, sovereign_mode=True)
    engine = getattr(opensource, engine_name)(config)

    report = engine.run(str(tmp_path / "nothing-here.bin"), "a" * 64, "pe")

    assert report.ran is False
    assert "sovereign" in (report.unavailable_reason or "").lower(), report.unavailable_reason


@pytest.mark.parametrize("engine_name", ENGINES)
def test_turning_it_off_gives_the_operator_their_integration_back(worker, engine_name) -> None:
    """Sovereign mode is a switch, not a removal. An operator who turns it off
    has said out loud that samples may leave, and the engine must then work."""
    config_mod, opensource = worker
    pytest.importorskip("requests")
    config = _configured(config_mod, sovereign_mode=False)
    engine = getattr(opensource, engine_name)(config)

    assert engine.available()
    assert engine.unavailable_reason is None


@pytest.mark.parametrize("engine_name", ENGINES)
def test_an_unconfigured_engine_is_not_reported_as_a_refusal(worker, engine_name) -> None:
    """"Not set up" and "refused" must not read the same. The whole point of the
    sovereignty design is that a refusal is visible; a refusal printed for every
    integration the operator never configured would bury the real ones."""
    config_mod, opensource = worker
    config = config_mod.Config(worker_token="t", sovereign_mode=True)
    engine = getattr(opensource, engine_name)(config)

    assert not engine.available()
    assert engine.unavailable_reason is None


def test_the_default_is_on(worker) -> None:
    """A sovereignty guarantee an operator must remember to switch on is one that
    fails the day someone forgets — the same default the backend uses."""
    config_mod, _opensource = worker
    assert config_mod.Config().sovereign_mode is True
    assert config_mod.Config.from_env().sovereign_mode is True


@pytest.mark.parametrize("value,expected", [
    ("false", False), ("False", False), ("0", False), ("no", False), ("off", False),
    ("true", True), ("1", True), ("yes", True),
    # A typo on a switch that governs egress must not read as "off".
    ("flase", True), ("", True), ("maybe", True),
])
def test_the_flag_is_parsed_the_way_the_backend_parses_it(worker, monkeypatch, value, expected) -> None:
    config_mod, _opensource = worker
    monkeypatch.setenv("SOVEREIGN_MODE", value)
    assert config_mod.Config.from_env().sovereign_mode is expected


@pytest.mark.parametrize("engine_name", ENGINES)
def test_each_engine_names_a_destination_the_operator_can_find(worker, engine_name) -> None:
    """A refusal that names something absent from `/api/capabilities` sends the
    operator looking for a setting that is not there."""
    from app.sovereignty import DESTINATIONS

    _config_mod, opensource = worker
    engine = getattr(opensource, engine_name)
    assert engine.destination in DESTINATIONS, engine.destination


def test_every_uploading_engine_goes_through_the_choke_point(worker) -> None:
    """The next REST sandbox client must inherit the gate rather than re-add it.

    Blunt on purpose: this module's whole job is handing sample files to other
    hosts, so a class here that is not an `_HttpSandboxEngine` is a second egress
    path, which is the shape of the defect being closed.
    """
    _config_mod, opensource = worker

    built = opensource.build_external_engines(_configured(_config_mod, sovereign_mode=True))
    assert built, "no external engines were built"
    for engine in built:
        assert isinstance(engine, opensource._HttpSandboxEngine), type(engine)
        assert engine.destination, f"{type(engine).__name__} does not name its destination"
        assert not engine.available()
