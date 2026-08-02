"""`backend/.env` would have been baked into the shipped image.

`.dockerignore` said `.env`, `.env.*`, `*.db` and `.pytest_cache/`. In Docker's
matching rules a pattern without `**/` matches only at the ROOT of the build
context — and the Dockerfile does `COPY backend/ ./`, so everything under
`backend/` was in scope and none of those four patterns reached it.

Measured with a real build rather than argued, four files in one context:

    ./.env                    excluded
    ./sandbox.db              excluded
    ./backend/.env            COPIED INTO THE IMAGE
    ./backend/sandbox.db      COPIED INTO THE IMAGE
    ./backend/.pytest_cache/  COPIED INTO THE IMAGE

And it was live, not hypothetical: `/app/.pytest_cache` is in the deployed image
right now, from `backend/.pytest_cache`, with `.pytest_cache/` sitting in
`.dockerignore` the whole time. The same path would have shipped a `.env`.

The file already knew the rule — `**/__pycache__/` was written correctly on the
line above `.venv/`, which was not. That is what makes this worth a test rather
than a fix: the knowledge was there and the application of it drifted.

This does not shell out to Docker. It implements the subset of the ignore syntax
that this file actually uses and checks the paths that matter, so it runs in CI
and on a laptop with no daemon.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DOCKERIGNORE = REPO / ".dockerignore"


def _patterns() -> list[tuple[bool, str]]:
    """(negated, pattern) in file order. Last match wins, as Docker does it."""
    out: list[tuple[bool, str]] = []
    for raw in DOCKERIGNORE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        out.append((negated, line[1:] if negated else line))
    return out


def _to_regex(pattern: str) -> re.Pattern[str]:
    """Docker's pattern syntax, restricted to what this file uses.

    * a leading `/` anchors to the context root, and is otherwise implicit;
    * `**` spans any number of path segments;
    * `*` and `?` stay within one segment;
    * a trailing `/` means "this directory and everything under it";
    * `[...]` is a character class, as in `*.py[cod]`.
    """
    pattern = pattern.lstrip("/")
    directory = pattern.endswith("/")
    pattern = pattern.rstrip("/")

    parts: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if pattern.startswith("**/", index):
            # `**/foo` matches `foo` at any depth, including depth zero.
            parts.append("(?:[^/]+/)*")
            index += 3
        elif pattern.startswith("**", index):
            parts.append(".*")
            index += 2
        elif char == "*":
            parts.append("[^/]*")
            index += 1
        elif char == "?":
            parts.append("[^/]")
            index += 1
        elif char == "[":
            close = pattern.find("]", index)
            if close == -1:
                parts.append(re.escape(char))
                index += 1
            else:
                parts.append(pattern[index:close + 1])
                index = close + 1
        else:
            parts.append(re.escape(char))
            index += 1

    body = "".join(parts)
    return re.compile("^" + body + ("(?:/.*)?$" if directory else "(?:/.*)?$"))


def _ignored(path: str) -> bool:
    verdict = False
    for negated, pattern in _patterns():
        if _to_regex(pattern).match(path):
            verdict = not negated
    return verdict


#: Paths that MUST NOT reach the build context. Each one is a real thing that
#: appears in a working checkout of this repository.
MUST_BE_IGNORED = [
    # secrets — the reason this test exists
    ".env",
    "backend/.env",
    "backend/.env.local",
    "frontend/.env.local",
    "worker/.env",
    # local databases: the demo SQLite file lives beside the backend
    "sandbox.db",
    "backend/sandbox.db",
    "backend/smoke_run.db",
    "backend/test.db",
    "frontend/x.sqlite3",
    # quarantined samples — live malware must never be in an image layer
    "quarantine/ab/abcdef",
    "backend/quarantine/ab/abcdef",
    "backend/local-quarantine/x",
    "sample_corpus/evil.exe",
    "backend/sample_corpus/evil.exe",
    # build and tool droppings, one of which is in the shipped image today
    "backend/.pytest_cache/v/cache/nodeids",
    "backend/.mypy_cache/x",
    "backend/__pycache__/app.cpython-312.pyc",
    "backend/app/engine/__pycache__/pdf.cpython-312.pyc",
    "backend/.venv/pyvenv.cfg",
    ".wvenv/pyvenv.cfg",
    "frontend/node_modules/react/index.js",
]

#: And paths that MUST survive, because excluding them breaks the image.
MUST_BE_KEPT = [
    "backend/app/main.py",
    "backend/app/engine/analyzers/pdf.py",
    "backend/requirements.lock.txt",
    "backend/alembic.ini",
    "backend/migrations/env.py",
    "worker/agent.py",
    "worker/engines/opensource.py",
    "frontend/src/main.tsx",
    "frontend/package.json",
    "Dockerfile",
    "sbom.json",
    "README.md",
    # the example is deliberately re-included by a negation
    "backend/.env.example",
]


@pytest.mark.parametrize("path", MUST_BE_IGNORED)
def test_nothing_secret_or_local_reaches_the_build_context(path) -> None:
    assert _ignored(path), (
        f"{path} would be copied into the image. A pattern without `**/` matches "
        "only at the context root, and the Dockerfile copies backend/ wholesale."
    )


@pytest.mark.parametrize("path", MUST_BE_KEPT)
def test_the_image_still_gets_the_things_it_needs(path) -> None:
    assert not _ignored(path), (
        f"{path} is excluded from the build context — the image would be broken. "
        "Widening a pattern to `**/` can catch more than it was meant to."
    )


def test_the_root_only_patterns_are_root_only_on_purpose() -> None:
    """Two patterns are deliberately NOT `**/`-prefixed, and must stay that way.

    `/reports/` is generated output at the repository root; a `reports/`
    directory inside the frontend source tree would be source. `docs/` is the
    documentation tree, which is at the root by definition.
    """
    text = DOCKERIGNORE.read_text(encoding="utf-8")
    assert "\n/reports/\n" in text
    assert not _ignored("frontend/src/reports/Chart.tsx")
    assert _ignored("reports/run.pdf")
    assert _ignored("docs/licensing.md")


def test_the_matcher_agrees_with_the_measured_docker_behaviour() -> None:
    """A guard on the guard.

    These four outcomes were produced by an actual `docker build` against the
    OLD file. If this matcher cannot reproduce them, it is not modelling
    Docker and the assertions above mean nothing.
    """
    old = [(False, "*.db"), (False, ".env"), (False, ".env.*"), (False, ".pytest_cache/")]

    def ignored_by_old(path: str) -> bool:
        verdict = False
        for negated, pattern in old:
            if _to_regex(pattern).match(path):
                verdict = not negated
        return verdict

    assert ignored_by_old(".env") is True
    assert ignored_by_old("sandbox.db") is True
    assert ignored_by_old("backend/.env") is False
    assert ignored_by_old("backend/sandbox.db") is False
    assert ignored_by_old("backend/.pytest_cache/v") is False
