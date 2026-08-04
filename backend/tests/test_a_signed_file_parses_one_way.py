"""A signed envelope that parses two ways proves nothing about either.

`canonical_bytes` is deterministic: sorted keys, one byte sequence per document,
and the Ed25519 signature covers exactly those bytes. The DECODER was not
injective. `json.loads` accepts an object carrying the same key twice and
silently keeps the last one, so a complete fabricated report body can travel
inside a signed file as a duplicate key:

    {"schema": ..., "manifest": ..., "report": {...fabricated...},
                                     "report": {...the signed one...}}

The verifier parses that, keeps the second `report`, re-encodes it, and the
signature matches. A reader who opens the same bytes with another library, or
reads them by eye, sees the first. `attestation.py`'s own claim -- "not one bit
of the report, the manifest or the engine identification has changed since" --
is only true if every parse of the envelope yields the same document.

Both parsers are tested, because there are deliberately two: the backend's, and
the standalone `tools/verify_report.py` that a recipient runs on a machine with
none of this product installed. They are allowed to be separate copies; they are
not allowed to disagree about what a valid envelope is.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from app.engine import attestation

TOOLS = Path(__file__).resolve().parents[2] / "tools" / "verify_report.py"


@pytest.fixture(scope="module")
def standalone():
    """Load the recipient's verifier the way a recipient would: as a file."""
    spec = importlib.util.spec_from_file_location("verify_report", TOOLS)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


#: The attack, in the shape a signed export has.
FORGED = (
    '{"schema":"cyclowareness/attested-report-1",'
    '"manifest":{"product":"cyclowareness-sandbox"},'
    '"report":{"verdict":"clean","note":"the body a reader sees"},'
    '"report":{"verdict":"malicious","note":"the body the signature covers"}}'
)


def test_the_stdlib_really_does_accept_it() -> None:
    """The premise, asserted rather than assumed -- if Python ever changes this,
    the rest of the file is about a threat that no longer exists and should say
    so loudly rather than passing quietly."""
    parsed = json.loads(FORGED)
    assert parsed["report"]["verdict"] == "malicious", (
        "json.loads no longer keeps the last duplicate key; re-derive this test"
    )


def test_the_backend_refuses_a_duplicate_key() -> None:
    with pytest.raises(ValueError) as caught:
        attestation.loads_strict(FORGED)
    assert "duplicate" in str(caught.value).lower(), caught.value


def test_the_recipients_verifier_refuses_it_too(standalone) -> None:
    """The copy that matters most: it runs where nothing else of ours does."""
    with pytest.raises(ValueError) as caught:
        json.loads(FORGED, object_pairs_hook=standalone._reject_duplicate_keys)
    assert "duplicate" in str(caught.value).lower(), caught.value


def test_the_verifier_exits_nonzero_on_such_a_file(standalone, tmp_path, capsys) -> None:
    """End to end, the way an auditor meets it: a file, a command, a status."""
    path = tmp_path / "forged.signed.json"
    path.write_text(FORGED, encoding="utf-8")
    assert standalone.main([str(path)]) == 2
    assert "duplicate" in capsys.readouterr().out.lower()


def test_an_ordinary_envelope_still_parses(standalone) -> None:
    """The control. Refusing everything would also pass the tests above."""
    good = json.dumps({
        "schema": "cyclowareness/attested-report-1",
        "manifest": {"product": "cyclowareness-sandbox"},
        "report": {"verdict": "clean"},
        "signature": "AA==",
    })
    assert attestation.loads_strict(good)["report"]["verdict"] == "clean"
    assert json.loads(good, object_pairs_hook=standalone._reject_duplicate_keys)


def test_a_repeated_key_deeper_in_the_document_is_caught(standalone) -> None:
    """The hook has to apply at every level, not only the envelope's top."""
    nested = (
        '{"schema":"s","manifest":{},'
        '"report":{"reproducible":{"sha256":"aaa"},"reproducible":{"sha256":"bbb"}}}'
    )
    with pytest.raises(ValueError):
        attestation.loads_strict(nested)
    with pytest.raises(ValueError):
        json.loads(nested, object_pairs_hook=standalone._reject_duplicate_keys)
