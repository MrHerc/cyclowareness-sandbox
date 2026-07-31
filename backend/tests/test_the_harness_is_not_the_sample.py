"""A LICENSE file is not a program, and powershell.exe is not the script.

Two defects in the dynamic tier, both measured on the detonation host, both with
the same shape: something the ANALYSIS HARNESS did was recorded as something the
SAMPLE did.

1. **226 detonations of files Windows cannot execute.** `identify()` routes every
   `text/*` mime into family `script`, and `script` is detonatable, so LICENSE
   files, READMEs, man pages, CA bundles and `.desktop` entries were handed to a
   live Windows guest — 87 `.txt`, 42 `.md`, 39 with no extension at all. Each
   cost a guest and several minutes, and each came back describing the guest:
   rclone's `README.html` was reported with
   `capev2.ransomware_file_modifications`, and a LICENSE file with
   `capev2.process_creation_suspicious_location`.

2. **The interpreter's behaviour, scored against the script.** Detonating a
   `.ps1` runs powershell.exe, which loads AMSI at startup and whose .NET JIT
   emits code into unbacked memory — that is what a JIT is. Measured across every
   PowerShell script detonated here, including ripgrep's and fd's tab-completion
   scripts, which define a few functions and exit:

       capev2.unbacked_api_resolution        100% of .ps1   22% of PEs
       capev2.unbacked_library_load          100%           23%
       capev2.unbacked_dotnet_execution      100%            6%
       capev2.amsi_enumeration               100%           12%
       ... twelve more `unbacked_*` at 100%

   A signal that fires on 100% of a population cannot distinguish within it. It
   made `_rg.ps1` — a tab-completion script — `malicious` at 45.9, and that made
   ripgrep's release archive malicious with it.

Both were priced before being applied. Fix 1: no malware on the host is
inert-named with executable content, and the 88-sample fixture contains no
scripts at all. Fix 2: re-scored against every script-shaped malware sample on
the host — 17 files, 36 stored analyses — **0 lost**; 34 stay `malicious`, two
move from `malicious` to `suspicious`.
"""
from __future__ import annotations

import pytest

from app.api.dynamic import _needs_dynamic
from app.engine import identify, scoring
from app.engine.contracts import Signal
from app.engine.models import JobStatus


# --- 1. do not spend a guest on a file that cannot run ------------------------


class _Job:
    """The fields `_needs_dynamic` reads.

    `sample_deleted_at` belongs here even though every case below leaves it
    None: a stub missing a column the predicate reads does not model a row, it
    models a row that cannot exist -- and when the predicate learned to check
    retention, fifty-one tests failed on AttributeError rather than on anything
    about detonation.
    """

    def __init__(self, name, family="script", mime="text/plain",
                 status=JobStatus.COMPLETED, tiers=None, sample_deleted_at=None):
        self.original_name = name
        self.archive_path = None
        self.family = family
        self.mime = mime
        self.status = status
        self.tiers = tiers or {"dynamic": {"ran": False}}
        self.sample_deleted_at = sample_deleted_at


#: Every extension measured being detonated on the host that Windows will not run.
INERT = [
    "LICENSE", "COPYING", "NOTICE", "README", "README.md", "CHANGELOG.md",
    "notes.txt", "git-log.txt", "Eula.txt", "curl-ca-bundle.crt",
    "rclone.1", "upx.1", "syncthing.service", "syncthing.plist",
    "app.desktop", "config.conf", "data.json", "book.csv", "styles.css",
    "release.sig", "schema.xml", "rg.bash", "rg.fish", "rg.zsh",
    "sketch.ino", "vars.def", "README.html", "index.htm",
]

RUNNABLE = [
    ("install.ps1", "text/plain"),
    ("module.psm1", "text/plain"),
    ("setup.bat", "text/plain"),
    ("legacy.vbs", "text/plain"),
    ("dropper.js", "text/plain"),
    ("payload.hta", "text/plain"),
    ("stage.wsf", "text/plain"),
    ("tool.py", "text/plain"),
    ("import.reg", "text/plain"),
    ("shortcut.lnk", "text/plain"),
]


@pytest.mark.parametrize("name", INERT)
def test_a_file_windows_cannot_run_is_not_detonated(name) -> None:
    assert not _needs_dynamic(_Job(name))


@pytest.mark.parametrize("name,mime", RUNNABLE)
def test_a_script_windows_runs_is_still_detonated(name, mime) -> None:
    assert _needs_dynamic(_Job(name, mime=mime))


@pytest.mark.parametrize("mime", [
    "text/x-powershell", "text/x-msdos-batch", "text/vbscript",
    "text/javascript", "text/x-python", "text/x-shellscript", "application/hta",
])
def test_content_beats_the_name(mime) -> None:
    """A PowerShell dropper renamed `notes.txt` is still detonated. The gate asks
    whether there is an execution path, never whether the name is honest."""
    assert _needs_dynamic(_Job("notes.txt", mime=mime))


@pytest.mark.parametrize("family", ["pe", "elf", "office", "pdf"])
def test_only_the_script_family_is_gated(family) -> None:
    """A PE, an ELF, an Office document and a PDF have an execution path by
    construction — nothing about them is decided by their extension here."""
    assert _needs_dynamic(_Job("whatever.bin", family=family, mime="application/octet-stream"))


def test_the_gate_does_not_reopen_a_finished_or_refused_detonation() -> None:
    assert not _needs_dynamic(_Job("a.ps1", tiers={"dynamic": {"ran": True}}))
    assert not _needs_dynamic(_Job("a.ps1", tiers={"dynamic": {"refused": True}}))
    assert not _needs_dynamic(_Job("a.ps1", status=JobStatus.RUNNING))


def test_html_is_not_an_execution_path() -> None:
    """Double-clicking a local HTML file opens a browser; a browser rendering a
    page is not the sample executing on the host. rclone's README.html was
    detonated and came back with `ransomware_file_modifications`."""
    assert not identify.has_execution_path(".html", "text/html")
    assert identify.has_execution_path(".hta", "text/html")


# --- 2. the interpreter is not the script ------------------------------------


def _signal(sid: str, severity: str = "high") -> Signal:
    return Signal(id=sid, title=sid, severity=severity, detail="", evidence={})


INTERPRETER = sorted(scoring.family_ambient("script"))


@pytest.mark.parametrize("sid", INTERPRETER)
def test_the_interpreters_own_behaviour_does_not_accuse_a_script(sid) -> None:
    assert scoring.effective_severity(_signal(sid), family="script") == "low"


@pytest.mark.parametrize("sid", INTERPRETER)
def test_the_same_observation_still_accuses_a_compiled_binary(sid) -> None:
    """Unbacked code execution in a PE is manual mapping or a reflective loader,
    and it fires on 6-23% of them rather than 100%. This must NOT become global."""
    assert scoring.effective_severity(_signal(sid), family="pe") == "high"
    assert scoring.effective_severity(_signal(sid)) == "high"


def test_a_script_that_actually_does_something_is_untouched() -> None:
    for sid in ("script.download_and_execute", "script.encoded_command",
                "script.amsi_or_etw_tamper", "script.persistence",
                "capev2.mass_data_encryption", "capev2.persistence_autorun",
                "capev2.credential_dumping", "yara.powershell_download_cradle"):
        assert scoring.effective_severity(_signal(sid), family="script") == "high", sid


def test_a_completion_script_is_not_a_dropper() -> None:
    """`_rg.ps1` in full: the interpreter's entire startup footprint and nothing
    else. It was `malicious` at 45.9."""
    signals = [_signal(sid) for sid in INTERPRETER]
    score, _detail = scoring.rule_score(signals, family="script")
    ungated, _d = scoring.rule_score(signals)
    assert score < 30, (score, "still above the suspicious threshold")
    assert ungated > score


def test_one_real_finding_still_lands_among_the_interpreter_noise() -> None:
    """Demoting the noise must not deafen the engine."""
    signals = [_signal(sid) for sid in INTERPRETER]
    signals += [_signal("script.download_and_execute"), _signal("script.encoded_command")]
    score, _detail = scoring.rule_score(signals, family="script")
    assert score >= 30, score


def test_the_family_list_is_only_about_the_interpreter() -> None:
    """A later edit that drops a real behaviour in here would give every script a
    free pass on it. Everything present must be host-runtime shaped."""
    allowed = ("unbacked_", "amsi_enumeration", "creates_suspended_process",
               "resumethread_remote_process", "reads_memory_remote_process",
               "terminates_remote_process")
    for sid in INTERPRETER:
        assert sid.startswith("capev2."), sid
        assert any(token in sid for token in allowed), sid


def test_family_demotion_is_off_by_default() -> None:
    """`assess` without a family demotes nothing — the stricter direction — so no
    existing caller silently gains a waiver."""
    assert scoring.family_ambient(None) == frozenset()
    assert scoring.family_ambient("") == frozenset()
    assert scoring.family_ambient("pe") == frozenset()
