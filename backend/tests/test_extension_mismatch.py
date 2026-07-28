"""A file whose extension is documented for its format is not in disguise.

`generic.extension_mismatch` is the engine's strongest deception signal — HIGH
severity, and the only static signal that grants the `deception` capability. It
fires when the claimed extension is absent from the canonical list for the
content that was sniffed.

That list was the four common PE extensions, so it called every other legitimate
one a lie. Measured on a real corpus run: Python's own embeddable distribution
ships eleven `.pyd` files — C extension modules, PE by definition — and every one
came out `malicious` at 60-66 with `Win32.Riskware.ExtensionMismatch` as the
threat name. curl's `curl-ca-bundle.crt`, a PEM trust store, scored 81.1.

This is the same mistake as the false positives before it, in another costume:
an observation ("the extension is not one I listed") read as a finding ("this
file is disguising itself"). The difference from the others is that this list CAN
be completed — which extensions a format legitimately uses is a fact about the
format, not an open-ended claim about what benign software does.
"""
from __future__ import annotations

import pytest

from app.engine import identify

#: PE payload: the DOS header is all the sniffer reads.
PE = b"MZ" + b"\x90\x00" * 32 + b"\x00" * 256

PE_EXTENSIONS = [
    ".exe", ".dll", ".sys", ".scr", ".pyd", ".node", ".ocx",
    ".cpl", ".drv", ".ax", ".mui", ".tsp", ".efi", ".msstyles",
]

PEM = (
    b"-----BEGIN CERTIFICATE-----\n"
    b"MIIBkTCB+wIJAOxV0nHRMcQeMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl\n"
    b"-----END CERTIFICATE-----\n"
)
CERT_EXTENSIONS = [".crt", ".cer", ".pem", ".key", ".pub", ".csr", ".asc"]


@pytest.mark.parametrize("extension", PE_EXTENSIONS)
def test_a_pe_under_any_of_its_own_extensions_is_not_a_mismatch(tmp_path, extension) -> None:
    path = tmp_path / f"module{extension}"
    path.write_bytes(PE)
    got = identify.identify(str(path), path.name)
    assert got.family == "pe"
    assert not got.extension_mismatch, (
        f"a PE named {path.name} was reported as disguising itself; "
        f"{extension} is a documented extension for this format"
    )


@pytest.mark.parametrize("extension", CERT_EXTENSIONS)
def test_pem_material_is_text_not_a_disguise(tmp_path, extension) -> None:
    path = tmp_path / f"bundle{extension}"
    path.write_bytes(PEM)
    got = identify.identify(str(path), path.name)
    assert not got.extension_mismatch, (
        f"{path.name} was reported as disguising itself; PEM is text by design"
    )


# --- and the signal still works ---------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["invoice.pdf", "photo.jpg", "report.docx", "notes.txt", "data.csv", "song.mp3"],
)
def test_a_pe_wearing_a_document_extension_is_still_caught(tmp_path, name) -> None:
    """The actual attack. Widening the PE list must not blunt this."""
    path = tmp_path / name
    path.write_bytes(PE)
    got = identify.identify(str(path), path.name)
    assert got.extension_mismatch, f"a PE named {name} was NOT flagged"


def test_the_capability_still_follows_from_the_signal() -> None:
    """`deception` must still be reachable — the fix narrows what fires it, not
    whether firing it means anything."""
    from app.engine import capabilities
    from app.engine.contracts import Signal

    signal = Signal(
        id="generic.extension_mismatch", title="x", severity="high", detail="", evidence={}
    )
    assert "deception" in capabilities.evidence_capabilities(signal)


def test_the_pe_extension_list_has_no_document_extensions() -> None:
    """A guard on the guard: widening this list is how the signal gets blunted.

    If someone ever adds `.pdf` or `.doc` here to silence a false positive, the
    deception signal stops working for the case it exists for, and nothing else
    would notice.
    """
    pe_extensions = next(
        exts for magic, _mime, _desc, exts in identify._MAGIC if magic == b"MZ"
    )
    forbidden = {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf",
        ".txt", ".csv", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip",
    }
    assert not (set(pe_extensions) & forbidden), (
        f"document extensions in the PE list: {sorted(set(pe_extensions) & forbidden)}"
    )
