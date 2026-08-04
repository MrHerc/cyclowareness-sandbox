"""A trace nobody could read must not come back as "nothing found".

`native_linux._analyse_trace` builds its behaviour out of `_CALL_RE` matches.
The regex matched none of the lines the engine's own strace invocation
(`-f -tt`) produces, so `calls` was empty on every run, every accumulator stayed
empty, and the tail of the function filed

    native.benign_trace  "No malicious behaviour observed in the trace"

which is a clean bill of health issued by a parse that read nothing at all.

The chosen repair is (b) of two: the engine reports `ran=False` with a reason
until the parser is fixed against a real captured trace. A tier that says "did
not run" is a state the report already presents honestly. A wrong "clean" is
not, and it is the one an analyst acts on.

Two distinct failures must stay distinct, which is what most of this file is
about:

  * lines arrived and none parsed  -> the parser is broken, say so
  * no lines arrived at all        -> the jail never started, a different fault

Collapsing them would hide the second behind the first.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

WORKER = Path(__file__).resolve().parents[2] / "worker"
if str(WORKER) not in sys.path:
    sys.path.insert(0, str(WORKER))


@pytest.fixture()
def engine():
    from engines import native_linux  # type: ignore

    class _Config:
        engine_timeout_seconds = 30
        worker_name = "test"

    return native_linux.NativeLinuxEngine(_Config())


@pytest.fixture()
def report():
    from engines.base import Report  # type: ignore

    return Report(engine="native-linux", worker="test")


#: Real strace output in the format this engine requests. If `_CALL_RE` is ever
#: fixed, these lines are what it has to match -- so this fixture doubles as the
#: specification for that work.
REAL_TRACE = """\
1234  10:11:12.131415 execve("/tmp/sample", ["/tmp/sample"], 0x7ffd /* 12 vars */) = 0
1234  10:11:12.141516 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
1234  10:11:12.151617 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 4
1234  10:11:12.161718 connect(4, {sa_family=AF_INET, sin_port=htons(4444)}, 16) = -1 ECONNREFUSED
1234  10:11:12.171819 write(1, "hello\\n", 6) = 6
1234  10:11:12.181920 exit_group(0) = ?
"""


def test_lines_that_parse_to_nothing_report_did_not_run(engine, report) -> None:
    """The defect itself, at the shape that shipped."""
    engine._analyse_trace(REAL_TRACE, report, timed_out=False)

    assert report.ran is False, (
        "a trace whose every line failed to parse was reported as a completed "
        "analysis"
    )
    assert report.unavailable_reason, "a tier that did not run has to say why"
    assert "parser" in report.unavailable_reason.lower()
    assert not report.signals, (
        "no signal may survive a parse that read nothing -- least of all "
        "native.benign_trace"
    )


def test_it_never_files_a_clean_verdict_off_an_unread_trace(engine, report) -> None:
    """The specific sentence this exists to prevent."""
    engine._analyse_trace(REAL_TRACE, report, timed_out=False)
    ids = {s.get("id") for s in report.signals}
    assert "native.benign_trace" not in ids, ids


def test_an_empty_trace_is_a_different_failure(engine, report) -> None:
    """The jail never started. That is not a parser bug and must not be
    reported as one, or the real cause is hidden behind the wrong sentence."""
    engine._analyse_trace("", report, timed_out=False)

    assert report.facts.get("trace_lines") == 0
    # `ran` stays True here: the engine did run, the trace was simply empty, and
    # the existing benign/timeout handling owns that case.
    assert report.ran is True, report.unavailable_reason


def test_the_line_count_is_recorded_either_way(engine, report) -> None:
    """`trace_lines` beside `syscalls_parsed` is what makes the gap visible in
    the stored facts: 0 of 6 parsed is a sentence a reader can act on."""
    engine._analyse_trace(REAL_TRACE, report, timed_out=False)
    assert report.facts["trace_lines"] == 6
    assert report.facts["syscalls_parsed"] == 0, (
        "if this is non-zero the parser has been fixed -- delete the guard "
        "above and this assertion with it, and put the real corpus number here"
    )


def test_a_parsed_trace_still_reports_normally(engine, report) -> None:
    """The guard must not swallow a working parse.

    Built from whatever `_CALL_RE` actually accepts today, so this test keeps
    holding after the parser is repaired rather than pinning the broken state.
    """
    from engines import native_linux  # type: ignore

    probe = '1234  10:11:12.131415 execve("/tmp/x", ["/tmp/x"], 0x0) = 0'
    if not native_linux._CALL_RE.match(probe.strip()):
        pytest.skip(
            "the parser still matches nothing -- this test becomes meaningful "
            "the moment it is fixed, and until then the guard above is the "
            "behaviour under test"
        )
    engine._analyse_trace(probe + "\n", report, timed_out=False)
    assert report.ran is True
    assert report.facts["syscalls_parsed"] >= 1
