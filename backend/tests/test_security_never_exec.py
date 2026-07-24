"""The load-bearing invariant: the static engine can never execute a sample.

Every ``.py`` under ``app/engine`` (analyzers included) is parsed and checked for
any construct that could run a subprocess or evaluate code — ``subprocess``,
``os.system``/``os.popen``, ``eval``/``exec``, ``Popen``, ``pty``, ``os.spawn*``,
the legacy ``commands`` module. If any one of them ever appears as *real code*,
this test fails and the whole security posture of the product is in question.

The check tokenises each file and inspects only NAME/OP tokens, deliberately
ignoring string and comment tokens. That distinction is essential rather than
pedantic: the script analyzer's whole job is to *detect* ``IEX``, ``eval(`` and
``exec(`` in a hostile sample, so those words appear in its regex literals. A
naive substring scan would flag those strings and could never pass — which would
make it a test nobody trusts. Ignoring string contents means a match here is
always an actual call site, never a detection pattern.

The off-host ``worker/`` tree is exempt by construction: it lives outside
``app/engine`` and is the one place detonation is permitted.
"""
from __future__ import annotations

import io
import tokenize
from pathlib import Path

import pytest

ENGINE_DIR = Path(__file__).resolve().parent.parent / "app" / "engine"

#: Bare identifiers that must never appear as executable code in the engine.
FORBIDDEN_NAMES = {
    "subprocess",
    "Popen",
    "pty",
    "eval",
    "exec",
    "commands",  # the Python 2 shell-out module
    "system",  # os.system
    "popen",  # os.popen / os.popen2...
    "spawn",  # os.spawn*
    "spawnl",
    "spawnv",
    "spawnve",
    "execv",
    "execve",
    "execvp",
    "execl",
    "execlp",
    "fork",  # os.fork
    "forkpty",
    "startfile",  # os.startfile — Windows "open with default handler"
}


def _engine_py_files() -> list[Path]:
    files = [
        p
        for p in ENGINE_DIR.rglob("*.py")
        # The worker tree is the only place detonation is allowed. It does not
        # live under app/engine, but exclude defensively in case that changes.
        if "worker" not in p.parts and "__pycache__" not in p.parts
    ]
    assert files, f"no engine .py files found under {ENGINE_DIR}"
    return files


def _code_name_tokens(source: str) -> list[tokenize.TokenInfo]:
    """Every NAME/OP token, with string and comment tokens dropped."""
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    return [t for t in tokens if t.type in (tokenize.NAME, tokenize.OP)]


@pytest.mark.parametrize("path", _engine_py_files(), ids=lambda p: p.name)
def test_engine_file_contains_no_execution_primitive(path: Path):
    source = path.read_text(encoding="utf-8")
    tokens = _code_name_tokens(source)

    names = {t.string for t in tokens if t.type == tokenize.NAME}
    offending = names & FORBIDDEN_NAMES
    assert not offending, (
        f"{path} references execution primitive(s) {sorted(offending)} as code — "
        "the static engine must never be able to run a sample"
    )

    # os.system / os.popen / os.spawn* as attribute access: NAME('os') '.' NAME(x).
    for i in range(len(tokens) - 2):
        a, dot, b = tokens[i], tokens[i + 1], tokens[i + 2]
        if (
            a.type == tokenize.NAME
            and a.string == "os"
            and dot.type == tokenize.OP
            and dot.string == "."
            and b.type == tokenize.NAME
            and (b.string in {"system", "popen", "startfile", "fork", "forkpty"}
                 or b.string.startswith(("spawn", "exec")))
        ):
            pytest.fail(f"{path} calls os.{b.string} — forbidden in the static engine")


def test_no_engine_file_imports_subprocess():
    """A second, coarser net at the import level, in case a token slips the
    identifier check above (e.g. ``import subprocess as sp``)."""
    for path in _engine_py_files():
        source = path.read_text(encoding="utf-8")
        for token in _code_name_tokens(source):
            assert token.string != "subprocess", f"{path} imports/uses subprocess"
