"""The corpus had no PDFs because the fetcher was never asked for one.

The malware fetcher lived only on the detonation host, untracked, and its type
filter was a hand-written copy of the supported-extension list:

    WANTED_TYPES = {"exe", "dll", "doc", "docx", "xls", "xlsm", "xlsx",
                    "js", "vbs", "ps1", "jar", "rtf", "lnk", "msi", "iso"}

No `pdf`. So the corpus contained no PDFs, so `MIN_MALWARE_DETECTED` covered
none, and nothing caught the engine scoring NIST 800-53 higher than nearly every
genuine malicious PDF. A copied list drifted from the original, unreviewed, for
as long as the file was invisible to the repo.

`infra/detonation-host/fetch-malware-corpus.py` is now tracked and derives its
types from `SUPPORTED_EXTENSIONS` instead of copying them. This test is the thing
that keeps it derived: if someone pastes a literal set back in, or the parser
stops finding the constant, it fails here rather than silently narrowing the
corpus a year from now.

It parses the script rather than importing it -- the script is dash-named, takes
argv, and reaches the network.
"""
from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FETCHER = REPO / "infra" / "detonation-host" / "fetch-malware-corpus.py"
META = REPO / "backend" / "app" / "api" / "meta.py"


def _literal(source: Path, name: str):
    tree = ast.parse(source.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            return ast.literal_eval(node.value)
    return None


def test_the_fetcher_is_tracked_at_all() -> None:
    """It being untracked is what made the omission unreviewable."""
    assert FETCHER.exists(), f"{FETCHER} is missing"


def test_the_type_list_is_not_copied_into_the_fetcher() -> None:
    """A module-level literal set of types is the bug, not a style choice."""
    assert _literal(FETCHER, "WANTED_TYPES") is None, (
        "fetch-malware-corpus.py has a hand-written WANTED_TYPES again. Derive it "
        "from SUPPORTED_EXTENSIONS; a copy is what let `pdf` go missing."
    )


def test_the_fetcher_can_still_find_the_constant_it_parses() -> None:
    """The fetcher reads SUPPORTED_EXTENSIONS with `ast`, so it must stay a literal.

    If meta.py ever builds that list dynamically, the fetcher exits with a
    message saying to fix the parser. This fails first, in the suite, rather than
    the next time someone runs a corpus build.
    """
    extensions = _literal(META, "SUPPORTED_EXTENSIONS")
    assert extensions, (
        "SUPPORTED_EXTENSIONS is no longer a plain literal in app/api/meta.py; "
        "fetch-malware-corpus.py parses it and will now refuse to run."
    )
    assert ".pdf" in extensions
    assert all(e.startswith(".") for e in extensions), extensions


def test_the_fetcher_reads_the_supported_list_from_the_backend() -> None:
    """Prove the wiring, not just the absence of a copy."""
    source = FETCHER.read_text(encoding="utf-8")
    assert "SUPPORTED_EXTENSIONS" in source
    assert "meta.py" in source, "the fetcher must name the file it derives from"
