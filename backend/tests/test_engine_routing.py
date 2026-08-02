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

        # `sovereign_mode=False` is what a deployment that actually uses CAPE
        # has set: with it on — the default — the CAPE engine is unavailable by
        # design, because reaching it means uploading the sample to another host.
        # This file is about ROUTING, so it describes the deployment where both
        # engines can run.
        config = Config(
            worker_token="t", capev2_url="http://cape.invalid", sovereign_mode=False
        )
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


# --- the one unavailability an operator can actually fix ---------------------
#
# `agent.py:88-93` prints an engine's `unavailable_reason` when it has one, "so
# 'unavailable' is never read as a bug". Every engine had one except this one,
# which is the only engine whose absence is a package install. Startup read:
#
#     engine native   -> unavailable
#     engine qiling   -> unavailable: qiling is GPL-2.0 and we do not ship it...
#
# The licence stance explained itself at length; the missing `apt install
# firejail` did not. Measured on the reference host: strace present, firejail
# absent, 5,643 detonations all to CAPE, this engine never having run a sample.

def test_the_native_engine_names_the_binary_it_is_missing(engines, monkeypatch) -> None:
    native, _cape = engines
    monkeypatch.setattr(native, "_firejail", lambda: None)
    monkeypatch.setattr(native, "_strace", lambda: "/usr/bin/strace")

    assert native.available() is False
    reason = native.unavailable_reason
    assert reason, "the fixable unavailability is the one that must explain itself"
    assert native.config.firejail_bin in reason
    assert native.config.strace_bin not in reason.split(".")[0], (
        "only the MISSING binary should be named as missing"
    )


def test_both_missing_are_both_named(engines, monkeypatch) -> None:
    native, _cape = engines
    monkeypatch.setattr(native, "_firejail", lambda: None)
    monkeypatch.setattr(native, "_strace", lambda: None)
    reason = native.unavailable_reason
    assert native.config.firejail_bin in reason and native.config.strace_bin in reason


def test_an_available_engine_has_no_reason(engines, monkeypatch) -> None:
    native, _cape = engines
    monkeypatch.setattr(native, "_firejail", lambda: "/usr/bin/firejail")
    monkeypatch.setattr(native, "_strace", lambda: "/usr/bin/strace")
    assert native.available() is True
    assert native.unavailable_reason is None


def test_the_refusal_report_says_the_same_thing_as_the_log(engines, monkeypatch, tmp_path) -> None:
    """An operator reading a report and one reading the log are told the same
    thing, and both are told WHICH binary is missing."""
    native, _cape = engines
    monkeypatch.setattr(native, "_firejail", lambda: None)
    monkeypatch.setattr(native, "_strace", lambda: "/usr/bin/strace")

    sample = tmp_path / "s.elf"
    sample.write_bytes(b"\x7fELF" + b"\x00" * 64)
    report = native.run(str(sample), "a" * 64, "elf")

    assert report.ran is False
    assert native.config.firejail_bin in (report.unavailable_reason or "")
    assert "unconfined" in (report.unavailable_reason or "")
