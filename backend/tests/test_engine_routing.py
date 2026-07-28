"""Which engine gets which sample — and the one-package regression it hides.

`Agent._choose_engine` takes the FIRST available engine that supports a family,
and `NativeLinuxEngine` is first in priority. That engine runs a sample natively
on the worker's Linux host under firejail, and it is unavailable only because
firejail is not installed.

So the routing table is decided by an `apt install`. Until this file existed, the
native engine claimed `script` as well as `elf`, which meant installing firejail
would silently move every PowerShell, VBScript and JScript sample off the Windows
sandbox and onto a Linux host, where such a sample cannot run. Nothing would
error. The jail would report a process that did nothing, and a Windows script
downloader would come back with no signals while a working Windows guest sat idle
— this project's oldest failure mode, evidence getting quietly thinner.

The corpus has five Windows script samples that detonate correctly on CAPE today.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

WORKER = Path(__file__).resolve().parents[2] / "worker"


@pytest.fixture()
def engines():
    sys.path.insert(0, str(WORKER))
    try:
        from config import Config  # type: ignore
        from engines.native_linux import NativeLinuxEngine  # type: ignore
        from engines.opensource import CapeV2Engine  # type: ignore

        config = Config(worker_token="t", capev2_url="http://cape.invalid")
        yield NativeLinuxEngine(config), CapeV2Engine(config)
    finally:
        sys.path.remove(str(WORKER))


def test_the_native_linux_engine_claims_only_elf(engines) -> None:
    """It runs samples on a LINUX host. Only ELF is a Linux executable."""
    native, _ = engines
    assert native.supports("elf")
    for family in ("pe", "script", "office", "pdf"):
        assert not native.supports(family), (
            f"the native Linux engine claims '{family}'. Install firejail and every "
            f"{family} sample stops reaching the Windows sandbox."
        )


def test_windows_families_still_reach_the_windows_sandbox(engines) -> None:
    _, cape = engines
    for family in ("pe", "script", "office", "pdf"):
        assert cape.supports(family)


def test_installing_firejail_cannot_reroute_windows_samples(engines, monkeypatch) -> None:
    """The regression itself, driven through the real selection logic.

    Pretend firejail and strace are both present — the only thing standing
    between this deployment and the bug — and assert the routing does not move.
    """
    import agent as agent_mod  # type: ignore

    native, cape = engines
    monkeypatch.setattr(native, "_firejail", lambda: "/usr/bin/firejail")
    monkeypatch.setattr(native, "_strace", lambda: "/usr/bin/strace")
    assert native.available(), "the premise of this test is that firejail is installed"

    class _Agent(agent_mod.Agent):
        def __init__(self):  # no config, no engine probing
            self.engines = [native, cape]

    chosen = _Agent()
    assert chosen._choose_engine("elf") is native, "ELF should run natively on Linux"
    for family in ("pe", "script", "office", "pdf"):
        assert chosen._choose_engine(family) is cape, (
            f"{family} was routed to the Linux engine once firejail appeared"
        )


def test_an_unsupported_family_gets_no_engine(engines) -> None:
    """Better no engine than the wrong one: no engine is reported, not guessed."""
    import agent as agent_mod  # type: ignore

    native, cape = engines

    class _Agent(agent_mod.Agent):
        def __init__(self):
            self.engines = [native, cape]

    assert _Agent()._choose_engine("archive") is None
