"""A .docx is a ZIP, and a part nobody read is worth saying out loud.

`_CARRIED_FORMATS` is seventeen extensions. A .docx accepts arbitrary extra
parts and every mail gateway treats it as a document, so a payload named with
any extension outside that list was not read, not extracted, not listed and not
counted -- it left with a clean verdict and no sentence anywhere saying a part
had been skipped. The same shape as `gzip dropper.ps1`: a container the product
names and does not open.

Extending the extension list is the wrong repair and it is worth being precise
about why. `_CARRIED_FORMATS` enumerates what an ATTACKER might name a payload,
so it loses to the next extension forever. `_ORDINARY_RESOURCES` enumerates what
WORD produces, which is a closed set decided by Microsoft and present in every
legitimate document -- a list is the right shape there and the wrong shape here.
So the finding is not "this part is dangerous"; it is "this analyzer read the
XML, read the relationships, and cannot account for this."

The severity is `medium` for the same reason: an unaccounted part is a gap in
the examination, not proof of a payload.
"""
from __future__ import annotations

import hashlib
import io
import zipfile

import pytest

from app.engine import identify
from app.engine.analyzers import office
from app.engine.contracts import Sample

MINIMAL_DOC = (
    b'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/'
    b'wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>hello</w:t></w:r></w:p>'
    b"</w:body></w:document>"
)


def _docx(tmp_path, extra: list[tuple[str, bytes]]):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        zf.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships/>')
        zf.writestr("word/document.xml", MINIMAL_DOC)
        for name, data in extra:
            zf.writestr(name, data)
    path = tmp_path / "sample.docx"
    blob = buf.getvalue()
    path.write_bytes(blob)
    # Built the way the pipeline builds it -- the identifier decides the mime and
    # the family, so this fixture cannot drift from what production analyses.
    ident = identify.identify(str(path), "sample.docx")
    return Sample(
        path=str(path), size_bytes=len(blob),
        sha256=hashlib.sha256(blob).hexdigest(), md5=hashlib.md5(blob).hexdigest(),
        mime=ident.mime, magic=ident.magic, claimed_extension=ident.claimed_extension,
        original_name="sample.docx", extension_mismatch=ident.extension_mismatch,
        family=ident.family,
    )


def _ids(sample):
    result = office.analyze(sample)
    return {s.id: s for s in result.signals}


def test_a_part_with_an_unremarkable_extension_is_reported(tmp_path) -> None:
    """The evasion: a payload named so that no list recognises it."""
    ids = _ids(_docx(tmp_path, [("word/settings.dat", b"MZ" + b"\x00" * 4096)]))
    assert "office.part_not_examined" in ids, sorted(ids)
    signal = ids["office.part_not_examined"]
    assert signal.severity == "medium", signal.severity
    assert "word/settings.dat" in str(signal.evidence.get("parts")), signal.evidence


@pytest.mark.parametrize(
    "name",
    [
        "word/media/image1.jpeg",
        "word/media/image2.png",
        "word/fonts/font1.odttf",
        "word/theme/theme1.xml",
        "customXml/item1.xml",
        "docProps/thumbnail.emf",
    ],
)
def test_the_parts_word_itself_writes_are_not_reported(tmp_path, name: str) -> None:
    """A signal that fires on every document ever saved is worth nothing. These
    are what Office produces, so they are accounted for rather than flagged."""
    ids = _ids(_docx(tmp_path, [(name, b"\x00" * 512)]))
    assert "office.part_not_examined" not in ids, (
        f"{name} is an ordinary Office resource and must not read as unexamined: "
        f"{ids.get('office.part_not_examined')}"
    )


def test_a_plain_document_stays_silent(tmp_path) -> None:
    """The control. No extra parts, no finding."""
    assert "office.part_not_examined" not in _ids(_docx(tmp_path, []))


def test_the_count_is_reported_not_just_the_first_few(tmp_path) -> None:
    """The detail lists six; a reader deciding whether to open the package needs
    to know whether that is all of them."""
    extra = [(f"word/blob{n}.dat", b"\x00" * 64) for n in range(9)]
    signal = _ids(_docx(tmp_path, extra))["office.part_not_examined"]
    assert signal.evidence.get("count") == 9, signal.evidence
    assert len(signal.evidence.get("parts") or []) <= 16
